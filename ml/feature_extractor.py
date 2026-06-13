import re
import math
import ipaddress
from urllib.parse import urlparse
import requests

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'account', 'banking', 'signin', 
    'webscr', 'ebayisapi', 'confirm', 'password', 'reset', 'wallet', 
    'crypto', 'free', 'bonus', 'admin', 'paypal', 'ebay', 'amazon', 
    'microsoft', 'office365', 'google', 'netflix', 'apple', 'security'
]

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'rebrand.ly', 'is.gd', 
    'buff.ly', 'ow.ly', 'bit.do', 'db.tt', 'wp.me', 'tiny.cc', 'shorte.st', 
    'go2l.ink', 'adf.ly', 'lnkd.in', 'db.tt', 'qr.ae', 'adfoc.us', 'bc.vc'
}

def get_entropy(s: str) -> float:
    """Calculates the Shannon Entropy of a string."""
    if not s:
        return 0.0
    
    # Calculate probability of each character
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    
    # Calculate Shannon entropy
    entropy = - sum([p * math.log(p, 2) for p in prob])
    return round(entropy, 4)

def check_ip_in_domain(domain: str) -> int:
    """Checks if the domain is an IP address using python ipaddress."""
    # Remove brackets for IPv6 and split off port if present
    clean_domain = domain.strip('[]').split(':')[0]
    try:
        ipaddress.ip_address(clean_domain)
        return 1
    except ValueError:
        return 0

def extract_features(url: str, online: bool = False) -> dict:
    """
    Extracts 13 features from a URL.
    
    Parameters:
      - url: The URL to analyze.
      - online: If True, executes network checks like redirects.
      
    Returns:
      A dictionary of feature names and values.
    """
    # Ensure scheme is present for urlparse
    if not re.match(r'^https?://', url, re.IGNORECASE):
        parsed_url = urlparse('http://' + url)
        raw_url = 'http://' + url
    else:
        parsed_url = urlparse(url)
        raw_url = url

    netloc = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
    # Strip port number
    domain = netloc.split(':')[0]
    
    # 1. URL Length
    url_len = len(raw_url)
    
    # 2. Domain Length
    domain_len = len(domain)
    
    # 3. Number of Dots
    num_dots = raw_url.count('.')
    
    # 4. Number of Hyphens
    num_hyphens = raw_url.count('-')
    
    # 5. Number of Digits
    num_digits = sum(c.isdigit() for c in raw_url)
    
    # 6. Presence of IP Address
    has_ip = check_ip_in_domain(domain)
    
    # 7. Presence of @ Symbol
    has_at = 1 if '@' in raw_url else 0
    
    # 8. Presence of HTTPS
    has_https = 1 if raw_url.lower().startswith('https://') else 0
    
    # 9. Number of Subdomains
    if has_ip:
        num_subdomains = 0
    else:
        domain_parts = domain.split('.')
        # Filter empty strings and standard 'www'
        domain_parts = [p for p in domain_parts if p and p.lower() != 'www']
        num_subdomains = max(0, len(domain_parts) - 2)
        
    # 10. Suspicious Keywords
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in raw_url.lower())
    
    # 11. Entropy Score
    entropy = get_entropy(raw_url)
    
    # 12. URL Shortener Detection
    is_shortener = 1 if domain.lower() in SHORTENERS else 0
    
    # 13. Redirect Detection
    has_redirect = 0
    if online:
        try:
            # We follow redirects with requests.get stream=True (supported by all webservers)
            response = requests.get(raw_url, allow_redirects=True, timeout=3.0, stream=True, headers={'User-Agent': 'Mozilla/5.0'})
            if len(response.history) > 0:
                has_redirect = 1
        except Exception:
            has_redirect = 0

    return {
        "url_length": url_len,
        "domain_length": domain_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "has_ip": has_ip,
        "has_at": has_at,
        "has_https": has_https,
        "num_subdomains": num_subdomains,
        "suspicious_keywords": keyword_count,
        "entropy": entropy,
        "is_shortener": is_shortener,
        "has_redirect": has_redirect
    }

def get_feature_names():
    """Returns the exact ordering of features for the ML model input."""
    return [
        "url_length",
        "domain_length",
        "num_dots",
        "num_hyphens",
        "num_digits",
        "has_ip",
        "has_at",
        "has_https",
        "num_subdomains",
        "suspicious_keywords",
        "entropy",
        "is_shortener",
        "has_redirect"
    ]

def get_vector(features_dict: dict) -> list:
    """Converts a features dictionary to a flat list ordered correctly for the model."""
    names = get_feature_names()
    return [features_dict[name] for name in names]

