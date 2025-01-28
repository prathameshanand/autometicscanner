import os
import logging
from django.shortcuts import render
from .forms import TaskForm
from .files.xss import VulnerabilityScanner, read_xss_payloads
from .files.app import WebsiteInfoGatherer
from .files.finder import Finder  # Ensure Finder is imported

class VulnerabilityView:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.payload_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'myapp',
            'files',
            'xsspayload.txt'
        )
        self.logger.debug(f"Payload file path: {self.payload_path}")
        
        if not os.path.exists(self.payload_path):
            self.logger.error(f"Payload file not found at: {self.payload_path}")
            raise FileNotFoundError(f"Payload file not found at: {self.payload_path}")

    def home(self, request):
        context = {}
        url = request.POST.get("url")
        if url:
            # Call Finder and gather results
            finder = Finder(url)
            finder.run()
            finder_results = finder.get_results()  # Use the new function to get results
            context["finder_results"] = {
                "valid_matches": finder_results.get("valid_matches", []),
                "unvalidated_matches": finder_results.get("unvalidated_matches", [])
            }  # Use finder_results for context

            # Call WebsiteInfoGatherer
            gatherer = WebsiteInfoGatherer(url)
            info = gatherer.gather_all_info()

            # Structure results for display
            context["results"] = {
                "Metadata": info.get("Metadata", {}),
                "Domain": info.get("Domain", "No domain info available."),
                "IP": info.get("IP", "No IP address found."),
                "Technology": info.get("Technology", "No technology stack found."),
                "SSL": info.get("SSL", "No SSL certificate found."),
                "Performance": info.get("Performance", "No performance metrics found."),
                "Content": info.get("Content", "No content analysis found."),
                "Security": info.get("Security", "No security features found."),
                "Geo": info.get("Geo", "No geolocation found."),
                "Robots": info.get("Robots", "No robots.txt found."),
                "Sitemap": info.get("Sitemap", "No sitemap.xml found."),
                "Social": info.get("Social", "No social media links found."),
                "Backlinks": info.get("Backlinks", "No backlinks or authority found."),
                "WordPress": info.get("WordPress", "No WordPress detected.")
            }
            context["url"] = url
        return render(request, "home.html", context)

try:
    vulnerability_view = VulnerabilityView()
    home = vulnerability_view.home
except FileNotFoundError as e:
    logging.error(f"Failed to initialize VulnerabilityView: {e}")
    def home(request):
        return render(request, "home.html", {"error": "System configuration error. Please contact administrator."})
