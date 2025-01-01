# main.py

import requests
from directory_traversal import test_directory_traversal
from ssrf_test import test_ssrf
from http_methods_test import test_insecure_http_methods
from security_misconfigurations import test_security_misconfigurations
from sensitive_info_disclosure import test_sensitive_info_disclosure
from playwright.sync_api import sync_playwright

def discover_input_fields(page):
    form_elements = page.query_selector_all("form")
    input_fields = []
    for form in form_elements:
        inputs = form.query_selector_all("input, select, textarea, button")
        for input_element in inputs:
            name = input_element.get_attribute("name")
            if name:
                input_fields.append((form, input_element, name))
    return input_fields

def run_tests(url):
    print(f"Running tests on {url}")

    # Using Playwright to discover input fields
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url)
        input_fields = discover_input_fields(page)
        
        # Run individual vulnerability tests
        print("\nTesting for Directory Traversal...")
        test_directory_traversal(url, input_fields)
        
        print("\nTesting for SSRF...")
        test_ssrf(url, input_fields)

        print("\nTesting for Insecure HTTP Methods...")
        test_insecure_http_methods(url)
        
        print("\nTesting for Security Misconfigurations...")
        test_security_misconfigurations(url)

        print("\nTesting for Sensitive Information Disclosure...")
        test_sensitive_info_disclosure(url, input_fields)

        browser.close()

# Main entry point for the script
if __name__ == '__main__':
    url = input("Enter the URL to test: ").strip()
    run_tests(url)
