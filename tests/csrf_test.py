import requests

# CSRF test payload
csrf_test_payload = {
    'username': 'test_user',
    'password': 'test_password',
    'csrf_token': 'malicious_token'  # Test if CSRF tokens are missing
}

# Function to test CSRF vulnerabilities
def test_csrf(url, input_fields):
    print(f"Testing for CSRF on {url}")
    vulnerable_params = []
    for field in input_fields:
        name = field[2]
        csrf_token = csrf_test_payload.get('csrf_token')
        test_data = {name: csrf_token}
        try:
            response = requests.post(url, data=test_data)
            if response.status_code == 200 and 'csrf' not in response.text:
                print(f"Potential CSRF vulnerability detected in parameter: {name}")
                vulnerable_params.append(name)
        except Exception as e:
            print(f"Error testing CSRF on parameter: {name} - {e}")
    return vulnerable_params
