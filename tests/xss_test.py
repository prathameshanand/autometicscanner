from playwright.sync_api import sync_playwright
import time

# Define XSS payloads
xss_payloads = [
    '<script>alert("XSS")</script>',
    '<img src="x" onerror="alert(\'XSS\')">',
    '<svg/onload=alert("XSS")>',
    '<a href="javascript:alert(\'XSS\')">Click me</a>'
]

# Function to discover input fields
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

# Function to test XSS vulnerabilities
def test_xss(page, input_fields, url):
    print(f"Testing for XSS on {url}")
    vulnerable_params = []
    for form, input_element, name in input_fields:
        for payload in xss_payloads:
            try:
                if input_element.get_attribute("type") == "submit":
                    continue

                input_element = page.query_selector(f"input[name='{name}']") or page.query_selector(f"textarea[name='{name}']")
                if input_element is None:
                    continue
                
                page.wait_for_selector(f"input[name='{name}']", timeout=5000)
                input_element.fill(payload)
                
                submit_button = form.query_selector("button, input[type='submit']")
                if submit_button:
                    submit_button.click()
                    time.sleep(2)
                    if payload in page.content():
                        print(f"Potential XSS vulnerability detected in parameter: {name} with payload: {payload}")
                        vulnerable_params.append((name, payload))
            except Exception as e:
                print(f"Error testing XSS on parameter: {name} - {e}")
    return vulnerable_params
