package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "os/exec"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"
)

// Config parameters
type Config struct {
    UseTLS       bool   // Enable TLS
    CertFile     string // Path to certificate file
    KeyFile      string // Path to key file
    ServerPort   string // Server port
    UseAllowlist bool   // Enable allowlist checking
    RateLimit    int    // Requests per minute
}

// DNSRecord represents a DNS record with TTL information
type DNSRecord struct {
    Value string `json:"value"`
    TTL   int    `json:"ttl"`
}

// DNSRecords holds the different types of DNS records
type DNSRecords struct {
    Domain string      `json:"domain"`
    A      []DNSRecord `json:"a,omitempty"`
    AAAA   []DNSRecord `json:"aaaa,omitempty"`
    CNAME  []DNSRecord `json:"cname,omitempty"`
    TXT    []DNSRecord `json:"txt,omitempty"`
}

// AllowedDomains holds a list of allowed ZONES for DNS queries and allows zones and subdomains
type AllowedDomains struct {
    Domains []string `json:"domains"`
}

var (
    config         Config
    allowedDomains AllowedDomains
    logger         *log.Logger
    digRegexp      = regexp.MustCompile("\\s+")
    rateLimiter    = make(chan time.Time, 1)
    rateLimiterMux sync.Mutex
)

func init() {
    // logging
    file, err := os.OpenFile("dns-queries.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }
    logger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.LUTC)
}

func main() {
    loadConfig()
    setupRateLimiter()
    http.HandleFunc("/dns-query", handleDNSQuery)
    serverAddress := fmt.Sprintf(":%s", config.ServerPort)
    if config.UseTLS {
        log.Printf("Starting HTTPS server on port %s", config.ServerPort)
        log.Fatal(http.ListenAndServeTLS(serverAddress, config.CertFile, config.KeyFile, nil))
    } else {
        log.Printf("Starting HTTP server on port %s", config.ServerPort)
        log.Fatal(http.ListenAndServe(serverAddress, nil))
    }
}

func loadConfig() {
    config = Config{
        UseTLS:       false,
        CertFile:     "server.crt",
        KeyFile:      "server.key",
        ServerPort:   "8080",
        UseAllowlist: true,
        RateLimit:    60, // default to 60 rpm
    }

    if config.UseAllowlist {
        data, err := ioutil.ReadFile("allowed.json")
        if err != nil {
            log.Fatalf("Failed to read allowed.json: %v", err)
        }
        if err := json.Unmarshal(data, &allowedDomains); err != nil {
            log.Fatalf("Failed to unmarshal allowed.json: %v", err)
        }
    }
}

func setupRateLimiter() {
    rateLimiterMux.Lock()
    defer rateLimiterMux.Unlock()
    rateLimiter = make(chan time.Time, config.RateLimit)
    for i := 0; i < config.RateLimit; i++ {
        rateLimiter <- time.Now()
    }
    go func() {
        ticker := time.NewTicker(time.Minute / time.Duration(config.RateLimit))
        defer ticker.Stop()
        for t := range ticker.C {
            rateLimiter <- t
        }
    }()
}

func handleDNSQuery(w http.ResponseWriter, r *http.Request) {
    select {
    case <-rateLimiter:
    default:
        http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
        return
    }

    domain := r.URL.Query().Get("domain")
    nameserver := r.URL.Query().Get("nameserver")

    logger.Printf("Received query for domain: %s with nameserver: %s", domain, nameserver)
    if nameserver == "" {
        nameserver = "8.8.8.8" // set recursive endpoint
        logger.Printf("No nameserver specified. Defaulting to %s", nameserver)
    }

    if config.UseAllowlist && !isDomainAllowed(domain) {
        http.Error(w, "Domain is not allowed", http.StatusForbidden)
        logger.Printf("Domain %s is not allowed", domain)
        return
    }

    records, err := queryAllRecordTypes(domain, nameserver)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        logger.Printf("Failed to query domain %s: %s", domain, err.Error())
        return
    }

    records.Domain = domain

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(records)
    logger.Printf("Successfully queried domain: %s", domain)
}

func isDomainAllowed(domain string) bool {
    for _, allowed := range allowedDomains.Domains {
        if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
            return true
        }
    }
    return false
}

func queryAllRecordTypes(domain, nameserver string) (DNSRecords, error) {
    var records DNSRecords
    recordTypes := []string{"A", "AAAA", "CNAME", "TXT"}

    for _, recordType := range recordTypes {
        // Construct dig command to include TTL
        command := fmt.Sprintf("dig @%s %s %s +noall +answer", nameserver, domain, recordType)
        cmd := exec.Command("bash", "-c", command)

        // Execute dig command
        output, err := cmd.CombinedOutput()
        if err != nil {
            logger.Printf("Failed to execute dig command: %s, Error: %v, Output: %s", command, err, string(output))
            return records, fmt.Errorf("error executing dig command for %s record: %v, output: %s", recordType, err, string(output))
        }

        // Parse output to extract values and TTLs
        if err := parseDigOutput(recordType, string(output), &records); err != nil {
            logger.Printf("Failed to parse output for %s record: %v", recordType, err)
            return records, fmt.Errorf("error parsing output for %s record: %v", recordType, err)
        }
    }

    // Filter out empty record types
    if len(records.A) == 0 {
        records.A = nil
    }
    if len(records.AAAA) == 0 {
        records.AAAA = nil
    }
    if len(records.CNAME) == 0 {
        records.CNAME = nil
    }
    if len(records.TXT) == 0 {
        records.TXT = nil
    }

    return records, nil
}

func parseDigOutput(recordType, output string, records *DNSRecords) error {
    lines := strings.Split(strings.TrimSpace(output), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, ";") {
            continue
        }
        parts := digRegexp.Split(line, 5)
        if len(parts) < 5 {
            continue
        }
        ttl, err := strconv.Atoi(parts[1])
        if err != nil {
            continue
        }
        value := parts[4]
        switch recordType {
        case "A":
            records.A = append(records.A, DNSRecord{Value: value, TTL: ttl})
        case "AAAA":
            records.AAAA = append(records.AAAA, DNSRecord{Value: value, TTL: ttl})
        case "CNAME":
            records.CNAME = append(records.CNAME, DNSRecord{Value: strings.TrimSuffix(value, "."), TTL: ttl})
        case "TXT":
            records.TXT = append(records.TXT, DNSRecord{Value: strings.Trim(value, "\""), TTL: ttl})
        default:
            return fmt.Errorf("unsupported DNS record type: %s", recordType)
        }
    }
    return nil
}
