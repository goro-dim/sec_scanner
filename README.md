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
        <pre>cd &lt;your-repository&gt;</pre>
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

  
