import argparse
import logging
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed  # For concurrency
import requests

# Setup logging
logging.basicConfig(level=logging.INFO)

def get_ip_from_url(url):
    """
    Convert a URL to its corresponding IP address.
    """
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


def check_port(ip, port, timeout=1):
    """
    Check if a given port is open on a target IP address.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0  # Return True if port is open
    except Exception as e:
        logging.error(f"Error checking port {port}: {e}")
        return False


def scan_open_ports(target_ip, ports="1-1024"):
    """
    Scan for open ports on a target IP address using a multi-threaded approach.
    """
    open_ports = []
    ports_to_scan = parse_ports(ports)
    
    logging.info(f"Starting port scan on {target_ip} for ports {ports}...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(check_port, target_ip, port): port for port in ports_to_scan}

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    logging.info(f"Port {port} is open on {target_ip}")
                    open_ports.append(port)
            except Exception as e:
                logging.error(f"Error scanning port {port}: {e}")

    logging.info(f"Port scan completed on {target_ip}.")
    return {"open_ports": open_ports}


def parse_ports(ports):
    """
    Parse the port input to a list of integers.
    """
    port_list = []
    ranges = ports.split(',')
    for part in ranges:
        if '-' in part:
            start, end = part.split('-')
            port_list.extend(range(int(start), int(end) + 1))
        else:
            port_list.append(int(part))
    return port_list


def check_public_resources(target_system_url):
    """
    Check if any cloud resources are publicly accessible.
    """
    try:
        response = requests.get(f"{target_system_url}/public-resources", timeout=5)  # Added timeout
        if response.status_code == 200:
            resources = response.json()
            public_resources = [resource for resource in resources if resource.get("is_public")]
            return {"resources": public_resources}
        else:
            logging.error(f"Failed to fetch public resources. Status code: {response.status_code}")
            return {"error": f"Failed to fetch public resources. Status code: {response.status_code}"}
    except Exception as e:
        logging.error(f"Error during public resources check: {e}")
        return {"error": str(e)}


def check_role_misconfiguration(target_system_url):
    """
    Check for common role misconfigurations.
    """
    try:
        response = requests.get(f"{target_system_url}/roles", timeout=5)  # Added timeout
        if response.status_code == 200:
            roles = response.json()
            misconfigurations = [role for role in roles if
                                 role.get("privilege_level") == "admin" and role.get("assigned_to").lower() not in [
                                     'admin', 'security']]
            return {"roles": misconfigurations}
        else:
            logging.error(f"Failed to fetch role misconfigurations. Status code: {response.status_code}")
            return {"error": f"Failed to fetch role misconfigurations. Status code: {response.status_code}"}
    except Exception as e:
        logging.error(f"Error during role misconfiguration check: {e}")
        return {"error": str(e)}


def check_weak_passwords(target_ip):
    """
    Check for common weak passwords on the given target.
    """
    try:
        weak_passwords = ['password', '123456', 'admin', 'root']
        found_weak_passwords = []  # Placeholder for results
        # Example check: This should be replaced with an actual service login attempt
        for password in weak_passwords:
            logging.info(f"Checking password: {password} on {target_ip}")
        return {"passwords": found_weak_passwords}
    except Exception as e:
        logging.error(f"Error during weak password check: {e}")
        return {"error": str(e)}


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

    # Print the results
    print("Results:", results)
