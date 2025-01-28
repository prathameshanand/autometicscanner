def detect_technologies(html_content, headers):
    technologies = []

    # Check for WordPress
    if 'wp-content' in html_content or 'wp-includes' in html_content:
        technologies.append("WordPress")

    # Check for jQuery
    if 'jquery' in html_content.lower():
        technologies.append("jQuery")

    # Check for Bootstrap
    if 'bootstrap' in html_content.lower():
        technologies.append("Bootstrap")

    # Check for Angular
    if 'ng-app' in html_content:
        technologies.append("AngularJS")

    # Check for React
    if 'react' in html_content.lower():
        technologies.append("React")

    # Check for specific headers
    if 'x-powered-by' in headers:
        technologies.append(f"Powered by: {headers['x-powered-by']}")

    return technologies

if __name__ == "__main__":
    # Example usage
    sample_html = "<html>...</html>"  # Replace with actual HTML content
    sample_headers = {"x-powered-by": "Express"}  # Replace with actual headers
    detected_tech = detect_technologies(sample_html, sample_headers)
    print("Detected Technologies:", detected_tech)
