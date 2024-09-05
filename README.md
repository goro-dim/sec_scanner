<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

</head>
<body>

<h1>🛡️ Security Scanner: The Python-Fueled Defender 🧙‍♂️</h1>
<p><em>(Still being forged in the fires of development... 🔨🔥)</em></p>

<h2>Overview</h2>
<p>Welcome to <strong>Security Scanner</strong>, a multi-functional CLI and Flask-based web application crafted to serve as your vigilant guardian against security vulnerabilities! This magical tool allows adventurers (a.k.a. security analysts and system administrators) to:</p>

<ul>
    <li>🔍 <strong>Scan open ports</strong> on a given IP or URL, exposing potential entry points for digital goblins.</li>
    <li>📂 <strong>Check for publicly accessible resources</strong> that might let the wrong types wander where they shouldn't.</li>
    <li>⚔️ <strong>Identify potential role misconfigurations</strong> that could lead to unsavory privileges.</li>
    <li>🕵️‍♂️ <strong>Detect weak passwords</strong> and protect against sneaky password-thieving trolls.</li>
</ul>

<p>The aim of this project is to provide both a user-friendly GUI and a powerful command-line interface that even the least arcane of wizards (newbies) can use to interact with powerful security tools.</p>

<h2>Features</h2>
<ul>
    <li>🌐 <strong>Port Scanning</strong>: Harnesses Python's socket library with asynchronous support to quickly scan for open ports on a given IP address or URL.</li>
    <li>🔍 <strong>Public Resources Check</strong>: Identifies publicly accessible resources that may be exposed unintentionally. (Currently under development—patience, young wizard!)</li>
    <li>⚖️ <strong>Role Misconfiguration Check</strong>: Analyzes roles and permissions to identify potential misconfigurations. (Also in the works...)</li>
    <li>🔑 <strong>Weak Password Check</strong>: Tests common weak passwords to identify vulnerabilities in your defenses.</li>
    <li>🖥️ <strong>User-Friendly GUI</strong>: A Flask-based web interface makes interaction easy for all, no command-line incantations required.</li>
    <li>🛠️ <strong>Easy SAP BTP Integration</strong>: Thanks to the <code>manifest.yml</code> file, integrating this project with SAP BTP is as easy as casting a basic spell.</li>
    <li>🖥️ <strong>Enhanced CLI Scanner</strong>: The CLI version of the scanner (<code>scanner_cli.py</code>) now supports asynchronous operations, formatted output, and selective scanning options.</li>
</ul>

<h2>Prerequisites</h2>
<p>Before you start your adventure, make sure you have the following artifacts in your inventory:</p>
<ul>
    <li>🧙‍♂️ Python 3.8 or higher</li>
    <li>📦 <code>pip</code> package manager</li>
</ul>

<h2>Installation</h2>
<p>Follow these steps to set up the project on your local machine:</p>
<ol>
    <li><strong>Clone the Repository:</strong>
        <pre><code>git clone https://github.com/goro-dim/sec_scanner.git
cd sec_scanner</code></pre>
    </li>
    <li><strong>Create a Virtual Environment:</strong>
        <pre><code>python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`</code></pre>
    </li>
    <li><strong>Install Required Packages:</strong>
        <pre><code>pip install -r requirements.txt</code></pre>
    </li>
</ol>

<h2>Usage</h2>

<h3>Flask-Based GUI</h3>
<p>To start the web-based GUI and use the scanner:</p>
<ol>
    <li><strong>Run the Flask Server:</strong>
        <pre><code>python server.py</code></pre>
    </li>
    <li><strong>Access the GUI:</strong>
        <p>Open your web browser and navigate to <a href="http://127.0.0.1:5000/">http://127.0.0.1:5000/</a>.</p>
    </li>
</ol>

<h3>Enhanced CLI Scanner</h3>
<p>For those who prefer wielding their command-line magic directly, the project includes an enhanced CLI-based scanner, <code>scanner_cli.py</code>.</p>

<h4>Usage:</h4>
<p>To scan a target IP or URL for open ports and perform other security checks:</p>
<pre><code>python scanner_cli.py --ip 192.168.1.1 --ports 1-1000</code></pre>

<h4>Available Options:</h4>
<ul>
    <li><code>--ip</code>: Target IP address for port scanning.</li>
    <li><code>--url</code>: Target URL to resolve its IP address and perform security checks.</li>
    <li><code>--ports</code>: Port range to scan (e.g., 1-1024).</li>
</ul>

<h4>Example Scenarios:</h4>
<ul>
    <li>🛠️ <strong>Port Scanning</strong>: Provide an IP or URL and specify a range of ports (e.g., 1-500). The scanner will perform an asynchronous scan and display open ports.</li>
    <li>🔍 <strong>Public Resources Check</strong>: Provide a URL to check for publicly accessible resources. (Under development)</li>
    <li>⚔️ <strong>Role Misconfiguration Check</strong>: Provide a URL to analyze roles and identify potential misconfigurations. (In progress)</li>
    <li>🔑 <strong>Weak Password Check</strong>: Provide an IP address to check for commonly used weak passwords.</li>
</ul>

<h2>Input Validation and Security</h2>
<p>The application includes basic input validation to ensure proper format for IP addresses, URLs, and port ranges. Be sure to enter valid inputs, lest you summon an error!</p>

<h2>Contributing</h2>
<p>Contributions are welcome! To join the guild, please follow these steps:</p>
<ol>
    <li>Fork the repository.</li>
    <li>Create a new branch: <code>git checkout -b feature/your-feature</code>.</li>
    <li>Make your changes and commit them: <code>git commit -m 'Add new feature'</code>.</li>
    <li>Push to the branch: <code>git push origin feature/your-feature</code>.</li>
    <li>Submit a pull request.</li>
</ol>

<h2>Contact</h2>
<p>If you have any questions or suggestions, feel free to open an issue or contact me directly (check my profile for the enchanted details 🧙‍♂️).</p>

<h2>Acknowledgements</h2>
<ul>
    <li>Flask - The web framework used.</li>
    <li>Python - The programming language used to build this application.</li>
</ul>

<h2>Disclaimer</h2>
<p><em>This tool is intended for educational purposes only. Use it at your own risk, and always ensure you have proper authorization before scanning any systems. Remember, with great power comes great responsibility! 🕵️‍♂️</em></p>

</body>
</html>
