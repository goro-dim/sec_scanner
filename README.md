

<h1>Security Scanner</h1>
<h4>( Work in progress ... ) </h4>

<h2>Overview</h2>

<p>Security Scanner is a Flask-based web application designed to perform security scans. The application allows users to:</p>
<ul>
    <li>Scan open ports on a given IP or URL.</li>
    <li>Check for publicly accessible resources.</li>
    <li>Identify potential role misconfigurations.</li>
    <li>Detect weak passwords.</li>
</ul>

<p>The project aims to provide an easy-to-use GUI to interact with the scanning functionalities, making it accessible for security analysts and system administrators.</p>

<h2>Features</h2>

<ul>
    <li><strong>Port Scanning</strong>: Uses Nmap to scan for open ports on a given IP address or URL.</li>
    <li><strong>Public Resources Check</strong>: Identifies publicly accessible resources that might be exposed.</li>
    <li><strong>Role Misconfiguration Check</strong>: Analyzes roles and permissions to identify potential misconfigurations.</li>
    <li><strong>Weak Password Check</strong>: Tests common weak passwords to identify security vulnerabilities.</li>
    <li><strong>User-Friendly GUI</strong>: A web-based interface built with Flask for easy interaction.</li>
</ul>

<p><strong>Note:</strong> Currently, only the port scanning functionality is fully operational. Other functionalities like public resources check, role misconfiguration check, and weak password detection are a work in progress.</p>

<h2>Prerequisites</h2>

<p>Before you begin, ensure you have met the following requirements:</p>

<ul>
    <li>Python 3.6 or higher</li>
    <li><code>nmap</code> installed on your system</li>
    <li><code>pip</code> package manager</li>
</ul>

<h2>Installation</h2>

<p>Follow these steps to set up the project on your local machine:</p>

<ol>
    <li>
        <strong>Clone the Repository</strong>:
        <pre><code>git clone https://github.com/goro-dim/sec_scanner.git
cd sap-security-scanner
        </code></pre>
    </li>
    <li>
        <strong>Create a Virtual Environment</strong>:
        <pre><code>python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
        </code></pre>
    </li>
    <li>
        <strong>Install Required Packages</strong>:
        <pre><code>pip install -r requirements.txt</code></pre>
    </li>
    <li>
        <strong>Install Nmap</strong>:
        <p>Ensure Nmap is installed on your system. For installation instructions, refer to the <a href="https://nmap.org/download.html" target="_blank">Nmap official documentation</a>.</p>
    </li>
</ol>

<h2>Usage</h2>

<p>To start the web-based GUI and use the scanner:</p>

<ol>
    <li>
        <strong>Run the Flask Server</strong>:
        <pre><code>python server.py</code></pre>
    </li>
    <li>
        <strong>Access the GUI</strong>:
        <p>Open your web browser and navigate to <code>http://127.0.0.1:5000/</code>.</p>
    </li>
</ol>

<h3>Scanning Options</h3>

<ul>
    <li><strong>IP Address</strong>: Enter a valid IP address to scan for open ports and perform other security checks.</li>
    <li><strong>URL</strong>: Enter a URL to resolve its IP address and perform security checks.</li>
    <li><strong>Ports</strong>: Enter a range or list of ports to scan (e.g., <code>1-500</code>, <code>80,443</code>).</li>
</ul>

<h3>Example Scenarios</h3>

<ol>
    <li>
        <strong>Port Scanning</strong>:
        <p>Provide an IP or URL and specify a range of ports (e.g., <code>1-500</code>). Click "Start Scan" to begin scanning for open ports.</p>
    </li>
    <li>
        <strong>Public Resources Check</strong>:
        <p>Provide a URL to check for publicly accessible resources.</p>
    </li>
    <li>
        <strong>Role Misconfiguration Check</strong>:
        <p>Provide a URL to analyze roles and identify potential misconfigurations.</p>
    </li>
    <li>
        <strong>Weak Password Check</strong>:
        <p>Provide an IP address to check for commonly used weak passwords.</p>
    </li>
</ol>

<h2>Scanner CLI</h2>

<p>The project also includes a CLI-based scanner, <code>scanner_cli.py</code>, which allows users to perform scans directly from the command line interface.</p>

<h3>Usage</h3>

<pre><code>python scanner_cli.py --ip 192.168.1.1 --ports 1-1000</code></pre>

<p>Currently, only the port scanning functionality is available in the CLI. Other functionalities like public resources check, role misconfiguration check, and weak password detection are being developed.</p>

<h2>Input Validation and Security</h2>

<p>The application includes basic input validation to ensure proper format for IP addresses, URLs, and port ranges. Make sure to enter valid inputs to avoid errors.</p>



<h2>Contributing</h2>

<p>Contributions are welcome! Please follow these steps to contribute:</p>

<ol>
    <li>Fork the repository.</li>
    <li>Create a new branch: <code>git checkout -b feature/your-feature</code>.</li>
    <li>Make your changes and commit them: <code>git commit -m 'Add new feature'</code>.</li>
    <li>Push to the branch: <code>git push origin feature/your-feature</code>.</li>
    <li>Submit a pull request.</li>
</ol>


<h2>Contact</h2>

<p>If you have any questions or suggestions, feel free to open an issue or contact me directly <i>(contact info in profile)</i> </p>

<h2>Acknowledgements</h2>

<ul>
    <li><a href="https://flask.palletsprojects.com/" target="_blank">Flask</a> - The web framework used.</li>
    <li><a href="https://nmap.org/" target="_blank">Nmap</a> - The network scanning tool used for port scanning.</li>
    <li><a href="https://www.python.org/" target="_blank">Python</a> - The programming language used to build this application.</li>
</ul>

<h2>Disclaimer</h2>

<p>This tool is intended for educational purposes only. Use it at your own risk and always ensure you have proper authorization before scanning any systems.</p>

</body>
</html>
