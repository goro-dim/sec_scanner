import argparse
import requests
import logging
import socket
from urllib.parse import urlparse
from tabulate import tabulate  # Import tabulate for ASCII-style table

# Setup logging
logging.basicConfig(level=logging.INFO)

def get_ip_from_url(url):
    """Convert a URL to its corresponding IP address."""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        else:
            raise ValueError("Invalid URL or hostname cannot be extracted.")
    except socket.error as e:
        logging.error(f"Error resolving IP address: {e}")
        return None

def scan_open_ports(target_ip, ports="1-1024"):
    """Scan open ports using Python's socket library."""
    logging.info(f"Starting port scan on {target_ip} for ports {ports}...")
    open_ports = []
    ports_to_scan = parse_ports(ports)

    try:
        for port in ports_to_scan:
            if check_port(target_ip, port):
                logging.info(f"Port {port} is open on {target_ip}")
                open_ports.append(port)

        logging.info(f"Port scan completed on {target_ip}.")
        return {"open_ports": open_ports}

    except Exception as e:
        logging.error(f"Error during port scanning: {e}")
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

def check_endpoint(url: str, endpoint: str) -> dict:
    """Check if a given endpoint exists and is accessible."""
    try:
        response = requests.get(f"{url}{endpoint}", timeout=5)
        if response.status_code == 200:
            return {"endpoint": endpoint, "status": "Accessible"}
        else:
            logging.error(f"Endpoint {endpoint} returned status code: {response.status_code}")
            return {"endpoint": endpoint, "status": "Inaccessible"}
    except Exception as e:
        logging.error(f"Error checking endpoint {endpoint}: {e}")
        return {"endpoint": endpoint, "status": "Error: " + str(e)}

def check_public_resources(target_system_url):
    """Check if any cloud resources are publicly accessible."""
    return check_endpoint(target_system_url, "/public-resources")

def check_role_misconfiguration(target_system_url):
    """Check for common role misconfigurations."""
    return check_endpoint(target_system_url, "/roles")

def check_weak_passwords(target_ip):
    """Check for common weak passwords on the given target."""
    weak_passwords = ['password', '123456', 'admin', 'root']
    found_weak_passwords = []

    # Placeholder for results - This should be replaced with actual service login attempt logic
    for password in weak_passwords:
        logging.info(f"Checking password: {password} on {target_ip}")
        # Add the check logic and if found, add to found_weak_passwords

    return {"passwords": found_weak_passwords}

def display_results(results):
    """Display results in an ASCII-style table format."""
    # Prepare the data for tabulate
    open_ports_data = [["Port", "Status"]]
    open_ports = results.get('open_ports', {}).get('open_ports', [])
    for port in open_ports:
        open_ports_data.append([port, "Open"])

    public_resources = results.get('public_resources', {})
    public_resources_data = [["Endpoint", "Status"]]
    public_resources_data.append([public_resources.get('endpoint'), public_resources.get('status')])

    role_misconfigurations = results.get('role_misconfigurations', {})
    role_misconfigurations_data = [["Endpoint", "Status"]]
    role_misconfigurations_data.append([role_misconfigurations.get('endpoint'), role_misconfigurations.get('status')])

    weak_passwords = results.get('weak_passwords', {}).get('passwords', [])
    weak_passwords_data = [["Username", "Weak Password"]]
    for entry in weak_passwords:
        weak_passwords_data.append([entry['username'], entry['weak_password']])

    # Print results using tabulate
    print("\nOpen Ports:")
    print(tabulate(open_ports_data, headers="firstrow", tablefmt="fancy_grid"))

    print("\nPublic Resources:")
    print(tabulate(public_resources_data, headers="firstrow", tablefmt="fancy_grid"))

    print("\nRole Misconfigurations:")
    print(tabulate(role_misconfigurations_data, headers="firstrow", tablefmt="fancy_grid"))

    print("\nWeak Passwords:")
    print(tabulate(weak_passwords_data, headers="firstrow", tablefmt="fancy_grid"))

# Main function to handle arguments and call appropriate functions
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run security scans on a given target.")
    parser.add_argument('--ip', type=str, help="Target IP address for port scanning.")
    parser.add_argument('--url', type=str, required=True,
                        help="Target URL for checking public resources, role misconfigurations, and weak passwords.")
    parser.add_argument('--ports', type=str, default="1-1024", help="Port range to scan (default: 1-1024).")

    args = parser.parse_args()

    results = {}

    # Extract IP from URL if IP is not provided
    if not args.ip:
        args.ip = get_ip_from_url(args.url)
        if not args.ip:
            logging.error("Failed to resolve IP address from URL.")
            results['open_ports'] = {'error': 'Failed to resolve IP address from URL.'}
        else:
            logging.info(f"Resolved IP address from URL: {args.ip}")

    # Perform port scan if IP is valid
    if args.ip:
        open_ports = scan_open_ports(args.ip, args.ports)
        results['open_ports'] = open_ports
    else:
        results['open_ports'] = {'error': 'No valid IP address for port scan.'}

    # Perform URL-based checks
    public_resources = check_public_resources(args.url)
    role_misconfigurations = check_role_misconfiguration(args.url)
    weak_passwords = check_weak_passwords(args.url)  # Assuming this function can work with URLs

    results['public_resources'] = public_resources
    results['role_misconfigurations'] = role_misconfigurations
    results['weak_passwords'] = weak_passwords

    # Display the results in ASCII-style tables
    display_results(results)
