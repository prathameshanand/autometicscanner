import re
import requests
import time
from urllib.parse import urljoin
from playwright.sync_api import sync_playwright

from .api_validations import validate_key  # Updated import statement

class Finder:
    def __init__(self, url):
        self.url = url
        self.js_files = []
        self.results = {}
        self.regex_patterns = {
            'google_api': r'AIza[0-9A-Za-z-_]{35}',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
            'amazon_mws_auth_token': (
                r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-'
                r'[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            ),
            'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
            'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
            'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
            'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
            'twilio_api_key': r'SK[0-9a-fA-F]{32}',
            'twilio_account_sid': r'AC[a-zA-Z0-9]{60}',
            'twilio_app_sid': r'AP[a-zA-Z0-9]{60}',
            'paypal_braintree_access_token': (
                r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'
            ),
            'square_oauth_secret': (
                r'sq0csp-[0-9a-zA-Z]{32}|sq0[a-z]{3}-[0-9a-zA-Z]{22,43}'
            ),
            'square_access_token': r'sqOatp-[0-9a-zA-Z]{22}|EAAA[a-zA-Z0-9]{60}',
            'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
            'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
            'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
            'rsa_private_key': (
                r'-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----'
            ),
            'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
            'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
            'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            'slack_token': r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"',
            'SSH_privKey': (
                r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)"
            ),
            'Heroku_API_KEY': (
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-'
                r'[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
            ),
            'possible_Creds': r"(?i)(password\s*[`=:\"]+\s*[^\s]+)",
            'password': r'password\s*[`=:\"]+\s*[^\s]+'
        }

    def get_js_files(self):
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(self.url)
                page.wait_for_load_state("load")

                js_files = []
                scripts = page.query_selector_all("script[src]")
                for script in scripts:
                    script_url = script.get_attribute("src")
                    if script_url:
                        full_url = urljoin(self.url, script_url)
                        js_files.append(full_url)

                browser.close()
            return js_files
        except Exception as e:
            print(f"\n Error extracting JavaScript files: {e}\n")
            return []

    def find_sensitive_info(self, js_content, js_file):
        for key, pattern in self.regex_patterns.items():
            matches = re.findall(pattern, js_content)
            if matches:
                if key not in self.results:
                    self.results[key] = {"valid_matches": [], "unvalidated_matches": []}

                for match in matches:
                    if validate_key(key, match):  # Assume validate_key is implemented
                        self.results[key]["valid_matches"].append((match, js_file))
                        print(f"\nValid match found: {match} (Source: {js_file}) \n")
                    else:
                        self.results[key]["unvalidated_matches"].append((match, js_file))
                        print(f"\nUnvalidated match found: {match} (Source: {js_file})\n")

    def save_raw_output(self, filename="raw_output.txt"):
        try:
            with open(filename, "w") as file:
                file.write("--- VALID MATCHES ---\n")
                for key, value in self.results.items():
                    for match, js_file in value.get("valid_matches", []):
                        file.write(f"{match} (Source: {js_file})\n")

                file.write("\n--- UNVALIDATED MATCHES ---\n")
                for key, value in self.results.items():
                    for match, js_file in value.get("unvalidated_matches", []):
                        file.write(f"{match} (Source: {js_file})\n")
            print(f"Raw output saved as {filename}")
        except Exception as e:
            print(f"Error saving raw output: {e}")

    def save_structured_report(self, filename="structured_report.txt"):
        try:
            with open(filename, "w") as file:
                file.write("PENTESTING REPORT\n")
                file.write("=================\n")
                file.write("Gemini Analysis Results:\n\n")
                for key, value in self.results.items():
                    for match, js_file in value.get("valid_matches", []):
                        file.write(f"--- {key} ---\n")
                        file.write(f"Status: Valid\n")
                        file.write(f"Details: {match}\n")
                        file.write("Source Files:\n")
                        file.write(f"  - {js_file}\n")
                    for match, js_file in value.get("unvalidated_matches", []):
                        file.write(f"--- {key} ---\n")
                        file.write(f"Status: Unvalidated\n")
                        file.write(f"Details: {match}\n")
                        file.write("Source Files:\n")
                        file.write(f"  - {js_file}\n")
            print(f"Structured report saved as {filename}")
        except Exception as e:
            print(f"Error saving structured report: {e}")

    def run(self):
        self.js_files = self.get_js_files()
        if not self.js_files:
            print("No JavaScript files found.")
            return

        for js_file in self.js_files:
            try:
                response = requests.get(js_file)
                response.raise_for_status()
                self.find_sensitive_info(response.text, js_file)
            except requests.RequestException as e:
                print(f"Error fetching {js_file}: {e}")

        # Save raw output with all findings
        raw_output_file = "raw_output.txt"
        self.save_raw_output(raw_output_file)

        # Save structured report
        structured_report_file = "structured_report.txt"
        self.save_structured_report(structured_report_file)

    def get_results(self):
        """Return valid and unvalidated matches."""
        return self.results

if __name__ == "__main__":
    url = input("Enter the URL of the website to scan: ")
    finder = Finder(url)
    finder.run()
