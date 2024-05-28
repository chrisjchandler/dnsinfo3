use the readme for dnsinfo2 https://github.com/chrisjchandler/DNSINFO2/blob/main/README.md

+allowed.json file add zones you want lookups allowed in  if there is no match the lookup will fail
+ Added logging emits a dns-queries.log file with transaction timestamps whether they succeed or fail 

Big difference between dnsinfo2 and dnsinfo3 is that this version will not default to the host recursive in resolv.conf you either need to specify it in the code nameserver= or in the api call see other readme. commit uses google public dns



