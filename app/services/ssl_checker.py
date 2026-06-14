import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from app.services.whois_lookup import get_domain

def check_ssl(url: str) -> dict:
    """
    Checks the SSL/TLS certificate details for the domain of the URL.
    Returns issuer, valid dates, and verification status.
    """
    domain = get_domain(url)
    
    result = {
        "has_ssl": False,
        "issuer": "None",
        "subject": "None",
        "valid_from": None,
        "valid_to": None,
        "days_remaining": -1,
        "status": "No SSL Certificate Found",
        "verified": False
    }
    
    # Check if domain is an IP or local host
    if domain.lower() in ['localhost', '127.0.0.1']:
        result["status"] = "Local Host (SSL Not Applicable)"
        return result
        
    try:
        # 1. Verify if certificate is valid and trusted
        try:
            verify_context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3.0) as verify_sock:
                with verify_context.wrap_socket(verify_sock, server_hostname=domain) as verify_ssock:
                    result["verified"] = True
        except Exception:
            result["verified"] = False
            
        # 2. Retrieve certificate details without validation (CERT_NONE) to extract fields
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                
                # Parse binary cert using cryptography library
                cert = x509.load_der_x509_certificate(der_cert)
                
                # Extract Issuer CN and O
                try:
                    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except IndexError:
                    issuer_cn = "Unknown CN"
                try:
                    issuer_o = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
                except IndexError:
                    issuer_o = ""
                issuer_str = f"{issuer_o} ({issuer_cn})" if issuer_o else issuer_cn
                
                # Extract Subject CN
                try:
                    subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except IndexError:
                    subject_cn = "Unknown Subject"
                
                # Extract Validity dates (check newer UTC properties, fallback to deprecated ones)
                try:
                    dt_from = cert.not_valid_before_utc
                    dt_to = cert.not_valid_after_utc
                except AttributeError:
                    dt_from = cert.not_valid_before
                    dt_to = cert.not_valid_after
                    if dt_from.tzinfo is None:
                        dt_from = dt_from.replace(tzinfo=timezone.utc)
                    if dt_to.tzinfo is None:
                        dt_to = dt_to.replace(tzinfo=timezone.utc)
                        
                valid_from = dt_from.strftime("%Y-%m-%d %H:%M:%S")
                valid_to = dt_to.strftime("%Y-%m-%d %H:%M:%S")
                
                # Calculate remaining days
                now_utc = datetime.now(timezone.utc)
                delta = dt_to - now_utc
                days_remaining = delta.days
                
                if days_remaining < 0:
                    status = "Expired"
                else:
                    status = "Active" if result["verified"] else "Active (Untrusted/Self-Signed)"
                    
                result.update({
                    "has_ssl": True,
                    "issuer": issuer_str,
                    "subject": subject_cn,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "days_remaining": days_remaining,
                    "status": status
                })
                
    except Exception as e:
        result["status"] = f"SSL Handshake Failed: {str(e)}"
        
    return result

if __name__ == "__main__":
    print(check_ssl("google.com"))
    print(check_ssl("expired.badssl.com"))

