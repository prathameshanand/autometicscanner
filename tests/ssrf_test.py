# ssrf_test.py
def test_ssrf(url, input_fields):
    print(f"Testing for SSRF on {url}")
    vulnerable_params = []
    for field in input_fields:
        name = field[2]
        for payload in ["http://localhost", "http://127.0.0.1", "http://169.254.169.254", "http://0.0.0.0"]:
            test_url = f"{url}?{name}={payload}"
            response = requests.get(test_url)
            if response.status_code == 200 and "local" in response.text:  # You can add more condition checks for SSRF
                print(f"Potential SSRF vulnerability detected in parameter: {name} with payload: {payload}")
                vulnerable_params.append((name, payload))
    return vulnerable_params
