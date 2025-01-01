# security_misconfigurations.py

import requests

def test_security_misconfigurations(url):
    print(f"Testing for Security Misconfigurations on {url}")
    response = requests.get(url)
    headers = response.headers

    # Check for missing security headers
    if "X-Content-Type-Options" not in headers:
        print("Missing X-Content-Type-Options header")
    if "Strict-Transport-Security" not in headers:
        print("Missing Strict-Transport-Security header")
    if "X-Frame-Options" not in headers:
        print("Missing X-Frame-Options header (Clickjacking vulnerability)")
    if "X-XSS-Protection" not in headers:
        print("Missing X-XSS-Protection header")

    # Check for exposed server information
    if "Server" in headers and headers["Server"] == "Apache":
        print("Exposed web server information: Apache")
