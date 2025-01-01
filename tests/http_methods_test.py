# http_methods_test.py
def test_insecure_http_methods(url):
    print(f"Testing for Insecure HTTP Methods on {url}")
    methods = ["PUT", "DELETE", "PATCH"]
    for method in methods:
        response = requests.request(method, url)
        if response.status_code == 405:  # 405: Method Not Allowed means the method is allowed
            print(f"Potential Insecure HTTP Method vulnerability detected with method: {method}")
