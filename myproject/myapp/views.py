from django.shortcuts import render, redirect
from .forms import TaskForm, SignupForm
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import logging
from django.contrib.auth.decorators import login_required

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)




def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            # Create a new user
            user = User.objects.create_user(
                username=form.cleaned_data['username'],
                email=form.cleaned_data['email'],
                password=form.cleaned_data['password']
            )
            user.save()
            messages.success(request, "Account created successfully!")
            return redirect('login')  # Redirect to login page after signup
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

def login_view(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, "Invalid credentials")

    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('login')




logger = logging.getLogger(__name__)
from django.shortcuts import render
from playwright.sync_api import sync_playwright
import logging

logger = logging.getLogger(__name__)
@login_required
def home(request):
    context = {}
    if request.method == "POST":
        url = request.POST.get("url")
        if url:
            try:
                logger.debug(f"Scanning URL: {url}")
                results = perform_xss_scan(url)
                context["results"] = results
                context["url"] = url
            except Exception as e:
                logger.error(f"Error during scanning: {e}")
                context["error"] = "An error occurred during scanning."
    return render(request, "home.html", context)

def perform_xss_scan(url):
    """
    Perform a fully automated XSS scan on the given URL using payloads from xsspayload.txt
    """
    results = []
    
    # Read XSS payloads from the file
    payloads = read_xss_payloads("/home/kali/Music/djnagoprojects/myproject/myapp/xsspayload.txt")
    
    # Scan for XSS vulnerabilities by fuzzing input fields with payloads
    fuzzing_results = fuzz_input_fields(url, payloads)
    results.extend(fuzzing_results)
    
    return results

def read_xss_payloads(filename):
    """
    Reads the XSS payloads from a file and returns them as a list.
    """
    try:
        with open(filename, "r") as file:
            payloads = [line.strip() for line in file.readlines()]
        return payloads
    except FileNotFoundError:
        logger.error("Payload file not found.")
        return []

def fuzz_input_fields(url, payloads):
    """
    Fuzz input fields on the given URL with the payloads and check for XSS vulnerabilities.
    """
    results = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url)
        
        # Wait for the page to load and ensure the elements are visible
        page.wait_for_load_state("domcontentloaded")
        
        # Get all input fields (input, textarea, select, etc.)
        input_fields = page.query_selector_all("input, textarea, select, button")
        
        # Loop over each input field and fuzz with each payload
        for input_field in input_fields:
            for payload in payloads:
                try:
                    logger.debug(f"Injecting payload into input field: {payload}")
                    
                    # Fill the field with the payload
                    input_field.fill(payload)
                    
                    # Wait for the page to process the payload (e.g., form submission or DOM update)
                    page.wait_for_timeout(1000)  # Wait for 1 second to allow page update
                    
                    # Check if the payload is reflected in the page content
                    if payload in page.content():
                        logger.info(f"Potential XSS found with payload: {payload}")
                        results.append({
                            "input_field": input_field,
                            "payload": payload,
                            "status": "Vulnerable"
                        })
                    else:
                        results.append({
                            "input_field": input_field,
                            "payload": payload,
                            "status": "Not Vulnerable"
                        })
                    
                    # Optionally clear the field after testing each payload
                    input_field.fill("")  # Clear the input field

                except Exception as e:
                    logger.error(f"Error during fuzzing for field {input_field}: {e}")
        
        browser.close()
    
    return results
