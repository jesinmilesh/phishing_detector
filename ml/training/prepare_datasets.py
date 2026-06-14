import os
import argparse
import random
import pandas as pd
import numpy as np

def prepare_data(size="small"):
    os.makedirs('datasets', exist_ok=True)
    
    sizes = {
        "small": 2000,
        "medium": 20000,
        "large": 100000,
        "enterprise": 500000
    }
    
    total_samples = sizes.get(size, 2000)
    print(f"[*] Scaling dataset: Generating {total_samples} samples ({size} configuration)...")
    
    legitimate_domains = [
        "google.com", "yahoo.com", "bing.com", "wikipedia.org", "github.com",
        "stackoverflow.com", "reddit.com", "medium.com", "nytimes.com", "cnn.com",
        "bbc.co.uk", "amazon.com", "ebay.com", "walmart.com", "target.com",
        "netflix.com", "spotify.com", "apple.com", "microsoft.com", "linkedin.com",
        "twitter.com", "facebook.com", "instagram.com", "pinterest.com", "tumblr.com",
        "dropbox.com", "salesforce.com", "zoom.us", "slack.com", "trello.com",
        "cloudflare.com", "mozilla.org", "python.org", "w3schools.com", "geeksforgeeks.org",
        "gitlab.com", "bitbucket.org", "heroku.com", "digitalocean.com", "aws.amazon.com"
    ]
    
    phishing_brands = ["paypal", "chase", "bankofamerica", "wellsfargo", "netflix", "amazon", "apple", "google", "microsoft", "facebook", "instagram", "twitter"]
    phishing_keywords = ["login", "signin", "secure", "verify", "update", "account", "billing", "confirm", "security", "recovery", "support", "portal"]
    phishing_tlds = ["xyz", "info", "top", "work", "cfd", "online", "site", "click", "club", "shop", "vip", "icu", "ru", "cn", "cc"]
    
    # Generate legitimate URLs
    print("[*] Generating legitimate samples...")
    legit_urls = []
    generated_set = set()
    
    half_samples = total_samples // 2
    
    # Keep generating until we hit half_samples
    attempts = 0
    max_attempts = half_samples * 10
    
    while len(legit_urls) < half_samples and attempts < max_attempts:
        attempts += 1
        domain = random.choice(legitimate_domains)
        # Add random subdomains for complexity
        if random.random() > 0.8:
            sub = random.choice(["portal", "mail", "dev", "api", "secure", "login"])
            domain = f"{sub}.{domain}"
            
        path = random.choice(["", "/", "/about", "/contact", "/search?q=cyber", "/index.html", "/news", "/blog/post-234.html", "/dashboard/settings"])
        scheme = "https://" if random.random() > 0.05 else "http://"
        url = f"{scheme}{domain}{path}"
        
        if url not in generated_set:
            generated_set.add(url)
            legit_urls.append(url)
            
    df_legit = pd.DataFrame({"url": legit_urls, "label": 0})
    df_legit.to_csv("datasets/legitimate.csv", index=False)
    print(f"[+] Created datasets/legitimate.csv with {len(legit_urls)} samples.")
    
    # Generate phishing URLs in three split files
    print("[*] Generating phishing samples...")
    phish_splits = [[] for _ in range(3)]
    
    attempts = 0
    total_phish_needed = half_samples
    phish_generated = 0
    
    while phish_generated < total_phish_needed and attempts < max_attempts:
        attempts += 1
        split_idx = phish_generated % 3
        
        mode = random.choice(["domain_keyword", "long_subdomain", "ip_address"])
        brand = random.choice(phishing_brands)
        kw = random.choice(phishing_keywords)
        tld = random.choice(phishing_tlds)
        
        if mode == "domain_keyword":
            url = f"http://{brand}-{kw}.{tld}/login.php"
        elif mode == "long_subdomain":
            url = f"http://www.{brand}.com.verify-billing.{tld}/index.html"
        else:
            ip = f"{random.randint(10,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
            url = f"http://{ip}/{brand}/login.php"
            
        if url not in generated_set:
            generated_set.add(url)
            phish_splits[split_idx].append(url)
            phish_generated += 1
            
    for i, split in enumerate(phish_splits):
        df_phish = pd.DataFrame({"url": split, "label": 1})
        df_phish.to_csv(f"datasets/phishing{i+1}.csv", index=False)
        print(f"[+] Created datasets/phishing{i+1}.csv with {len(split)} samples.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Shield Dataset Scaler and Generator")
    parser.add_argument("--size", type=str, default="small", choices=["small", "medium", "large", "enterprise"], help="Dataset size configuration")
    args = parser.parse_args()
    
    prepare_data(args.size)
