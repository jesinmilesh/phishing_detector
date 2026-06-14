import os
import random
import pandas as pd

def prepare_data():
    os.makedirs('datasets', exist_ok=True)
    
    legitimate_domains = [
        "google.com", "yahoo.com", "bing.com", "wikipedia.org", "github.com",
        "stackoverflow.com", "reddit.com", "medium.com", "nytimes.com", "cnn.com",
        "bbc.co.uk", "amazon.com", "ebay.com", "walmart.com", "target.com",
        "netflix.com", "spotify.com", "apple.com", "microsoft.com", "linkedin.com",
        "twitter.com", "facebook.com", "instagram.com", "pinterest.com", "tumblr.com",
        "dropbox.com", "salesforce.com", "zoom.us", "slack.com", "trello.com",
        "cloudflare.com", "mozilla.org", "python.org", "w3schools.com", "geeksforgeeks.org"
    ]
    
    phishing_brands = ["paypal", "chase", "bankofamerica", "wellsfargo", "netflix", "amazon", "apple"]
    phishing_keywords = ["login", "signin", "secure", "verify", "update", "account", "billing", "confirm"]
    phishing_tlds = ["xyz", "info", "top", "work", "cfd", "online", "site"]
    
    # Legitimate urls
    legit_urls = []
    for _ in range(1000):
        domain = random.choice(legitimate_domains)
        path = random.choice(["", "/", "/about", "/contact", "/search?q=cyber", "/index.html", "/news"])
        scheme = "https://" if random.random() > 0.1 else "http://"
        legit_urls.append(f"{scheme}{domain}{path}")
        
    df_legit = pd.DataFrame({"url": legit_urls, "label": 0})
    df_legit.to_csv("datasets/legitimate.csv", index=False)
    print("Created datasets/legitimate.csv")
    
    # Phishing datasets split in three parts
    phish_urls1 = []
    for _ in range(300):
        brand = random.choice(phishing_brands)
        kw = random.choice(phishing_keywords)
        tld = random.choice(phishing_tlds)
        url = f"http://{brand}-{kw}.{tld}/login.php"
        phish_urls1.append(url)
    df_phish1 = pd.DataFrame({"url": phish_urls1, "label": 1})
    df_phish1.to_csv("datasets/phishing1.csv", index=False)
    print("Created datasets/phishing1.csv")

    phish_urls2 = []
    for _ in range(300):
        brand = random.choice(phishing_brands)
        kw = random.choice(phishing_keywords)
        tld = random.choice(phishing_tlds)
        url = f"http://www.{brand}.com.verify-billing.{tld}/index.html"
        phish_urls2.append(url)
    df_phish2 = pd.DataFrame({"url": phish_urls2, "label": 1})
    df_phish2.to_csv("datasets/phishing2.csv", index=False)
    print("Created datasets/phishing2.csv")

    phish_urls3 = []
    for _ in range(400):
        ip = f"{random.randint(10,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
        brand = random.choice(phishing_brands)
        url = f"http://{ip}/{brand}/login.php"
        phish_urls3.append(url)
    df_phish3 = pd.DataFrame({"url": phish_urls3, "label": 1})
    df_phish3.to_csv("datasets/phishing3.csv", index=False)
    print("Created datasets/phishing3.csv")

if __name__ == "__main__":
    prepare_data()
