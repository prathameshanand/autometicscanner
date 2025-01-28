import requests
import socket
import ssl
import whois
from bs4 import BeautifulSoup
import json
from urllib.parse import urlparse
import re
import logging
from .tech_detector import detect_technologies

class Utility:
    @staticmethod
    def validate_url(url):
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None

class WebsiteInfoGatherer:
    def __init__(self, url):
        self.url = url if url.startswith("http") else f"http://{url}"
        self.parsed_url = urlparse(self.url)
        self.domain = urlparse(url).netloc
        self.hostname = urlparse(self.url).hostname
        DEFAULT_TIMEOUT = 10
        response = requests.get(self.url, timeout=DEFAULT_TIMEOUT)

    def fetch_metadata(self):
        """मूलभूत मेटाडेटा मिळवा: शीर्षक, वर्णन, कीवर्ड."""  # Translated comment
        try:
            response = requests.get(self.url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            metadata = {
                'Title': soup.title.string if soup.title else 'No title',
                'Description': soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else 'No description',
                'Keywords': soup.find('meta', {'name': 'keywords'})['content'] if soup.find('meta', {'name': 'keywords'}) else 'No keywords'
            }
            return metadata
        except requests.exceptions.RequestException as e:
            return {"Error": f"Failed to fetch metadata: {e}"}

    def get_ssl_certificate(self):
        try:
            hostname = self.parsed_url.hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            return {
                "Common Name (CN)": cert.get("subject", [[("commonName", "")]])[0][0][1],
                "Issuer": cert.get("issuer", [[("commonName", "")]])[0][0][1],
                "Valid From": cert.get("notBefore"),
                "Valid To": cert.get("notAfter"),
                "Subject Alternative Names (SANs)": cert.get("subjectAltName", []),
            }
        except (ssl.SSLError, socket.error) as e:
            return {"Error": f"SSL प्रमाणपत्र मिळवण्यात अयशस्वी: {e}"}  # Translated error message

    def get_geolocation(self, ip_address):
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            if response.status_code == 200:
                data = response.json()
                return {
                    "IP": data.get("ip"),
                    "Country": data.get("country"),
                    "Region": data.get("region"),
                    "City": data.get("city"),
                    "Coordinates": data.get("loc"),
                }
            else:
                return {"Error": f"Geolocation मिळवण्यात अयशस्वी (Status: {response.status_code})"}
        except Exception as e:
            return {"Error": str(e)}

    def get_domain_info(self):
        return f"Domain: {self.domain}, Hostname: {self.hostname}"
    
    def get_robots_and_sitemap(self):
        try:
            robots_url = f"{self.url}/robots.txt"
            sitemap_url = f"{self.url}/sitemap.xml"
            logging.debug(f"Fetching robots.txt from: {robots_url}")
            logging.debug(f"Fetching sitemap.xml from: {sitemap_url}")
            robots_response = requests.get(robots_url, timeout=10)
            sitemap_response = requests.get(sitemap_url, timeout=10)
            robots = robots_response.text if robots_response.status_code == 200 else "Not Found"
            sitemap = sitemap_response.text if sitemap_response.status_code == 200 else "Not Found"
            logging.debug(f"Robots Response: {robots}")
            logging.debug(f"Sitemap Response: {sitemap}")
            return {"Robots": robots, "Sitemap": sitemap}
        except Exception as e:
            return f"robots.txt किंवा sitemap मिळवण्यात अयशस्वी: {e}"  # Translated error message

    def get_technology_stack(self):
        try:
            response = requests.get(self.url)
            html_content = response.text
            headers = response.headers
            technologies = detect_technologies(html_content, headers)
            return technologies if technologies else "Unknown"
        except Exception as e:
            logging.error(f"तंत्रज्ञान स्टॅक मिळवण्यात अयशस्वी: {e}")  # Translated error message
            return "Unknown"

    def fetch_ip_address(self):
        try:
            return socket.gethostbyname(self.domain)
        except socket.error as e:
            return {"Error": f"IP पत्ता मिळवण्यात अयशस्वी: {e}"}  # Translated error message
        
    def get_security_features(self):
        try:
            response = requests.get(self.url, timeout=10)
            headers = response.headers
            https_status = "Enabled" if self.url.startswith("https") else "Not Enabled"
            security_headers = {
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Not Found"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Not Found"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not Found"),
            }
            return {"HTTPS": https_status, "Security": security_headers}
        except Exception as e:
            return f"सुरक्षा वैशिष्ट्ये तपासण्यात अयशस्वी: {e}"  # Translated error message
    
    def get_content_analysis(self):
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.content, "html.parser")
            word_count = len(soup.get_text().split())
            images = len(soup.find_all("img"))
            scripts = len(soup.find_all("script"))
            language = soup.find("html").get("lang", "Unknown")
            return {
                "Word": word_count,
                "Image": images,
                "Script": scripts,
                "Language": language,
            }
        except Exception as e:
            return f"सामग्री विश्लेषण करण्यात अयशस्वी: {e}"  # Translated error message
    
    def get_social_media_links(self):
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.content, "html.parser")
            social_links = []
            for a_tag in soup.find_all("a", href=True):
                if any(platform in a_tag["href"] for platform in ["facebook.com", "twitter.com", "linkedin.com", "instagram.com","github.com","reddit.com", "discord.com"]):
                    social_links.append(a_tag["href"])
            return {"Social": social_links}
        except Exception as e:
            return f"सोशल मीडिया लिंक मिळवण्यात अयशस्वी: {e}"  # Translated error message
    
    def detect_wordpress(self):
        try:
            response = requests.get(self.url, timeout=10)
            if response.status_code == 200:
                if 'wp-content' in response.text or 'wp-includes' in response.text:
                    return {"WordPress": True}
                if '<meta name="generator" content="WordPress' in response.text:
                    return {"WordPress": True}
                wp_urls = ["/wp-login.php", "/wp-admin/", "/wp-content/"]
                for wp_url in wp_urls:
                    wp_check = requests.get(self.url + wp_url, timeout=5)
                    if wp_check.status_code == 200:
                        return {"WordPress": True}
            return {"WordPress": False}
        except Exception as e:
            return {"Error": str(e)}
    
    def get_performance_metrics(self):
        return {"Performance": "Use tools like Lighthouse or Google PageSpeed API for detailed metrics."}
    
    def get_backlinks_and_authority(self):
        return {"Backlinks": "Use APIs like Moz or Ahrefs for detailed insights."}
    
    def gather_all_info(self):
        ip = self.fetch_ip_address()
        return {
            "SSL": self.get_ssl_certificate(),
            "Performance": self.get_performance_metrics(),
            "IP": ip,
            "Metadata": self.fetch_metadata(),
            "Content": self.get_content_analysis(),
            "Security": self.get_security_features(),
            "Geo": self.get_geolocation(ip),
            "Robots": self.get_robots_and_sitemap(),
            "WordPress": self.detect_wordpress(),
            "Social": self.get_social_media_links(),
            "Backlinks": self.get_backlinks_and_authority(),
            "Domain": self.get_domain_info(),
            "Technology": self.get_technology_stack(),
        }

# Main script
if __name__ == "__main__":
    website_url = input("Enter the website URL: ")
    if not Utility.validate_url(website_url):
        print("Invalid URL. Please enter a valid website URL (e.g., https://example.com).")
    else:
        gatherer = WebsiteInfoGatherer(website_url)
        info = gatherer.gather_all_info()
        
        # Print results in a labeled format
        for section, details in info.items():
            print(f"\n=== {section} ===")
            if isinstance(details, dict):
                for key, value in details.items():
                    print(f"{key}: {value}")
            else:
                print(details)
