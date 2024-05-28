package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "os/exec"
    "strings"
)

// Conf parms 
type Config struct {
    UseTLS       bool   // Enable TLS
    CertFile     string // Path to certificate file
    KeyFile      string // Path to key file
    ServerPort   string // Server port
    UseAllowlist bool   // Enable allowlist checking
}

// for DNS reply
type DNSRecords struct {
    A     []string `json:"a,omitempty"`
    AAAA  []string `json:"aaaa,omitempty"`
    CNAME []string `json:"cname,omitempty"`
    MX    []string `json:"mx,omitempty"`
    NS    []string `json:"ns,omitempty"`
    TXT   []string `json:"txt,omitempty"`
}

// AllowedDomains holds a list of allowed ZONES for DNS queries and allows zones and subdomains
type AllowedDomains struct {
    Domains []string `json:"domains"`
}

var (
    config         Config
    allowedDomains AllowedDomains
    logger         *log.Logger
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
func handleDNSQuery(w http.ResponseWriter, r *http.Request) {
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
    recordTypes := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
    
    for _, recordType := range recordTypes {
        // Construct dig
        command := fmt.Sprintf("dig @%s %s %s +short", nameserver, domain, recordType)
        cmd := exec.Command("bash", "-c", command)

        // Execute dig
        output, err := cmd.CombinedOutput()
        if err != nil {
            logger.Printf("Failed to execute dig command: %s, Error: %v, Output: %s", command, err, string(output))
            return records, fmt.Errorf("error executing dig command for %s record: %v, output: %s", recordType, err, string(output))
        }

        // Parse output 
        if err := parseDigOutput(recordType, string(output), &records); err != nil {
            logger.Printf("Failed to parse output for %s record: %v", recordType, err)
            return records, fmt.Errorf("error parsing output for %s record: %v", recordType, err)
        }
    }
    return records, nil
}

func parseDigOutput(recordType string, output string, records *DNSRecords) error {
    results := strings.Split(strings.TrimSpace(output), "\n")
    switch recordType {
    case "A":
        records.A = append(records.A, results...)
    case "AAAA":
        records.AAAA = append(records.AAAA, results...)
    case "CNAME":
        for _, result := range results {
            if result != "" {
                records.CNAME = append(records.CNAME, strings.TrimSuffix(result, "."))
            }
        }
    case "MX":
        records.MX = append(records.MX, results...)
    case "NS":
        for _, result := range results {
            if result != "" {
                records.NS = append(records.NS, strings.TrimSuffix(result, "."))
            }
        }
    case "TXT":
        for _, result := range results {
            if result != "" {
                records.TXT = append(records.TXT, strings.Trim(result, "\""))
            }
        }
    default:
        return fmt.Errorf("unsupported DNS record type: %s", recordType)
    }
    return nil
}
