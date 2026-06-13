import socket
from typing import Any
import dns.resolver
from intelligence.whois_lookup import get_domain

def lookup_dns(url: str) -> dict:
    """
    Performs DNS queries for A, MX, NS, and TXT records of the domain.
    """
    domain = get_domain(url)
    
    records = {
        "A": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "status": "No Records Found"
    }
    
    # Try basic socket IP lookup first as a baseline
    try:
        ip = socket.gethostbyname(domain)
        records["A"].append(ip)
    except Exception:
        pass

    # Use dnspython to query MX, NS, TXT, and fallback A records
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    # Query A Records
    try:
        a_records = resolver.resolve(domain, 'A')
        for rdata in a_records:
            ip = str(rdata)
            if ip not in records["A"]:
                records["A"].append(ip)
    except Exception:
        pass

    # Query MX Records
    try:
        mx_records = resolver.resolve(domain, 'MX')
        for rdata in mx_records:
            rdata_any: Any = rdata
            records["MX"].append(f"{rdata_any.preference} {rdata_any.exchange}")
    except Exception:
        pass

    # Query NS Records
    try:
        ns_records = resolver.resolve(domain, 'NS')
        for rdata in ns_records:
            records["NS"].append(str(rdata))
    except Exception:
        pass

    # Query TXT Records
    try:
        txt_records = resolver.resolve(domain, 'TXT')
        for rdata in txt_records:
            rdata_any: Any = rdata
            # Clean up quotes
            txt_str = "".join([t.decode('utf-8') if isinstance(t, bytes) else str(t) for t in rdata_any.strings])
            records["TXT"].append(txt_str)
    except Exception:
        pass

    # Update status based on findings
    found_any = any(len(records[k]) > 0 for k in ["A", "MX", "NS", "TXT"])
    records["status"] = "Success" if found_any else "Lookup Failed / No Records"
    
    return records

if __name__ == "__main__":
    print(lookup_dns("google.com"))
    print(lookup_dns("nonexistent-domain-test-123456.xyz"))
