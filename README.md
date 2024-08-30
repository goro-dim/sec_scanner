
 <h1>Security Scanner Project</h1>
    <p>This project provides a security scanner that performs the following tasks:</p>
    <ul>
        <li>Scan for open ports on a given IP address.</li>
        <li>Check for public resources on a given URL.</li>
        <li>Check for role misconfigurations on a given URL.</li>
        <li>Check for weak passwords on a given IP address.</li>
    </ul>
    <h2>Setup and Installation</h2>
    <ol>
        <li>Clone the repository:</li>
        <pre>git clone https://github.com/goro-dim/sec_scanner.git</pre>
        <li>Navigate to the project directory:</li>
        <pre>cd sec_scanner</pre>
        <li>Create a virtual environment and activate it (optional but recommended):</li>
        <pre>python -m venv venv</pre>
        <pre>venv\Scripts\activate</pre>
        <li>Install required dependencies:</li>
        <pre>pip install -r requirements.txt</pre>
    </ol>
    <h2>Usage</h2>
    <p>To use the security scanner, run the <code>scanner.py</code> script with the following arguments:</p>
    <pre>python scanner.py --url &lt;target-url&gt; [--ip &lt;target-ip&gt;] [--ports &lt;port-range&gt;]</pre>
    <p>Example:</p>
    <pre>python scanner.py --url http://example.com --ports 1-500</pre>
    <h2>Components</h2>
    <h3>1. <code>scanner.py</code></h3>
    <p>The <code>scanner.py</code> script is a command-line tool that performs several security checks:</p>
    <ul>
        <li><strong>Port Scanning:</strong> Uses the Nmap library to scan for open ports on a given IP address.</li>
        <li><strong>Public Resources:</strong> Checks for publicly accessible resources on a given URL.</li>
        <li><strong>Role Misconfigurations:</strong> Identifies potential role misconfigurations on a given URL.</li>
        <li><strong>Weak Passwords:</strong> (Placeholder) Checks for common weak passwords on a given IP address.</li>
    </ul>
    <p>Run this script directly from the command line to perform these checks.</p>

 <h3>2. <code>server.py</code></h3>
    <p>The <code>server.py</code> file sets up a Flask web server to expose a RESTful API for scanning:</p>
    <ul>
        <li><strong>API Endpoints:</strong>
            <ul>
                <li><code>/</code> - A welcome endpoint.</li>
                <li><code>/scan</code> - A POST endpoint that accepts JSON payloads to perform security scans. It calls <code>scanner.py</code> functions to check open ports, public resources, role misconfigurations, and weak passwords.</li>
            </ul>
        </li>
        <li><strong>Integration:</strong> This Flask app integrates with the scanner functions to provide a web-based interface for performing security scans.</li>
    </ul>
    <p>To run the Flask server, use the command:</p>
    <pre>python server.py</pre>

 
