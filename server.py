from flask import Flask, request, jsonify, render_template
import requests
import concurrent.futures
import logging
import csv
from io import StringIO
import re
from urllib.parse import urlparse
import socket  # To resolve IP address from URL and scan ports
from werkzeug.exceptions import BadRequest
import waitress

# Initialize the Flask application
app = Flask(__name__, static_folder='static')
logging.basicConfig(level=logging.DEBUG)

# Regular expressions for input validation
IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
URL_REGEX = re.compile(r'^(http|https)://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(:[0-9]{1,5})?(/.*)?$')
PORTS_REGEX = re.compile(r'^[0-9,-]+$')  # Allows ports in formats like '22', '80,443', '1-1024'


@app.route('/')
def home():
    # Render the homepage with links to different functionalities
    return render_template('index.html')


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        # Retrieve data from the form
        ip = request.form.get('ip', '').strip()  # Optional
        url = request.form.get('url', '').strip()  # Optional
        ports = request.form.get('ports', '1-500').strip()  # Default ports if none provided

        # Validate input
        if not ip and not url:
            error_message = "Please provide either an IP address or a URL."
            return render_template('scan.html', error_message=error_message)

        if ip and not validate_ip(ip):
            error_message = "Invalid IP address format."
            return render_template('scan.html', error_message=error_message)

        if url and not validate_url(url):
            error_message = "Invalid URL format."
            return render_template('scan.html', error_message=error_message)

        if ports and not validate_ports(ports):
            error_message = "Invalid ports format. Please enter ports like '80,443' or '1-1024'."
            return render_template('scan.html', error_message=error_message)

        # If URL is provided and IP is not, resolve IP from the URL
        if url and not ip:
            try:
                ip = resolve_ip_from_url(url)
                logging.info(f"Resolved IP address from URL: {ip}")
            except Exception as e:
                error_message = f"Failed to resolve IP from URL: {e}"
                return render_template('scan.html', error_message=error_message)

        # Run all scanning functions
        open_ports = scan_open_ports(ip, ports) if ip else {"error": "IP not provided for port scan"}
        public_resources = check_public_resources(url) if url else {
            "error": "URL not provided for public resources check"}
        role_misconfigurations = check_role_misconfiguration(url) if url else {
            "error": "URL not provided for role misconfiguration check"}
        weak_passwords = check_weak_passwords(ip) if ip else {"error": "IP not provided for weak password check"}

        # Prepare the response
        response = {
            'open_ports': open_ports,
            'public_resources': public_resources,
            'role_misconfigurations': role_misconfigurations,
            'weak_passwords': weak_passwords
        }

        return render_template('scan_results.html', response=response)

    # Render the scan page with a form for input
    return render_template('scan.html')


def resolve_ip_from_url(url: str) -> str:
    """Resolve IP address from a given URL."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    # Resolve and return the IP address
    ip_address = socket.gethostbyname(domain)
    return ip_address


def validate_ip(ip: str) -> bool:
    """Validate the IP address format using a regex."""
    return bool(IP_REGEX.match(ip))


def validate_url(url: str) -> bool:
    """Validate the URL format using urllib and a regex."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and bool(URL_REGEX.match(url))
    except ValueError:
        return False


def validate_ports(ports: str) -> bool:
    """Validate the ports input format."""
    return bool(PORTS_REGEX.match(ports))


def scan_open_ports(target_ip: str, ports: str = "1-500") -> dict:
    """Scan open ports using Python's socket library."""
    open_ports = []
    ports_to_scan = parse_ports(ports)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(check_port, target_ip, port): port for port in ports_to_scan}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)

        return {"open_ports": open_ports}
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        return {"error": str(e)}


def parse_ports(ports: str) -> list:
    """Parse the port input to a list of integers."""
    port_list = []
    ranges = ports.split(',')
    for part in ranges:
        if '-' in part:
            start, end = part.split('-')
            port_list.extend(range(int(start), int(end) + 1))
        else:
            port_list.append(int(part))
    return port_list


def check_port(ip: str, port: int) -> bool:
    """Check if a given port is open on a target IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        return result == 0


def check_public_resources(url: str) -> dict:
    try:
        # Perform an HTTP GET request to check public resources
        response = requests.get(url)
        # For simplicity, just returning the URL and status code
        return {"resources": [{"url": url, "status_code": response.status_code}]}
    except requests.RequestException as e:
        logging.error(f"Failed to check public resources: {e}")
        return {"error": str(e)}


def check_role_misconfiguration(url: str) -> dict:
    # Dummy implementation for checking role misconfigurations
    # Replace with actual logic to analyze roles and permissions
    return {"roles": [{"role": "admin", "misconfiguration": False}]}


def check_weak_passwords(ip: str) -> dict:
    # Dummy implementation for checking weak passwords
    # Replace with actual logic to perform password strength analysis
    return {"passwords": [{"username": "admin", "weak_password": "admin123"}]}


if __name__ == '__main__':
    app.run()
