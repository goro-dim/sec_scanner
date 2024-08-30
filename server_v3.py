from flask import Flask, request, jsonify
import nmap
import requests
import concurrent.futures
import logging
import csv
from io import StringIO

# Initialize the Flask application
app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)


@app.route('/')
def home():
    return "Welcome to the Security Scanner API"


@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    ip = data.get('ip')
    url = data.get('url')
    ports = data.get('ports')

    # Run all scanning functions
    open_ports = scan_open_ports(ip, ports)
    public_resources = check_public_resources(url)
    role_misconfigurations = check_role_misconfiguration(url)
    weak_passwords = check_weak_passwords(ip)

    # Prepare the response
    response = {
        'open_ports': open_ports,
        'public_resources': public_resources,
        'role_misconfigurations': role_misconfigurations,
        'weak_passwords': weak_passwords
    }

    return jsonify(response)


def scan_open_ports(target_ip: str, ports: str = "1-500") -> dict:
    nm = nmap.PortScanner()
    try:
        # Using a ThreadPoolExecutor to handle timeouts
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submitting the Nmap scan task
            future = executor.submit(nm.scan, hosts=target_ip, ports=ports, arguments='-T4', timeout=60)
            # Waiting for the result with a timeout of 60 seconds
            future.result(timeout=60)

        # Getting scan results in CSV format
        scan_result = nm.csv()
        if scan_result:
            # Parse CSV to a structured format
            return {"open_ports": parse_nmap_csv(scan_result)}
        else:
            return {"error": "No scan results available"}
    except concurrent.futures.TimeoutError:
        return {"error": "Scan timed out"}
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        return {"error": str(e)}


def parse_nmap_csv(csv_data: str) -> list:
    """Parse Nmap CSV output to a list of dictionaries for better readability."""
    result = []
    csv_reader = csv.DictReader(StringIO(csv_data))
    for row in csv_reader:
        result.append(row)
    return result


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
    # Running the Flask app in debug mode
    app.run(debug=True)
