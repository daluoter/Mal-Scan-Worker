rule network_iocs {
    meta:
        description = "Observed HTTP/HTTPS URL; no destination reputation or malicious behavior verdict"
        author = "MalScan"
        classification = "informational"
        severity = "info"
    strings:
        $http = "http://" ascii
        $https = "https://" ascii
    condition:
        any of them
}

rule suspicious_network_patterns {
    meta:
        description = "Detects suspicious network communication patterns"
        author = "MalScan"
        severity = "medium"
    strings:
        $c2_ua1 = "User-Agent: Mozilla/4.0" ascii nocase
        $c2_ua2 = "User-Agent: Mozilla/5.0 (compatible; MSIE" ascii nocase
        $raw_socket = "SOCK_RAW" ascii
        $dns_txt = "TXT" ascii
        $dns_query = "nslookup" ascii nocase
        $powershell_download = "downloadstring" ascii nocase
        $wget = "wget " ascii nocase
        $curl = "curl " ascii nocase
        $certutil = "certutil" ascii nocase
        $bitsadmin = "bitsadmin" ascii nocase
    condition:
        2 of them
}

rule base64_url {
    meta:
        description = "Detects base64 encoded URLs"
        author = "MalScan"
        severity = "medium"
    strings:
        $b64_http1 = "aHR0cDov" ascii  // base64 of "http:/"
        $b64_http2 = "aHR0cHM6" ascii  // base64 of "https:"
    condition:
        any of them
}
