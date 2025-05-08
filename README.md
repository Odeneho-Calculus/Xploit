# XPLOIT: Targeted Database Enumeration via Parameter Injection

XPLOIT is a comprehensive web application security testing framework designed to identify and exploit URL parameter-based vulnerabilities to access backend database content. It provides a systematic approach to reconnaissance, vulnerability detection, enumeration, and data extraction.

<p align="center">
  <img src="data/logo.png" alt="XPLOIT Logo" width="200"/>
</p>

## 🔍 Features

- **Reconnaissance Module**: 
  - Analyzes target URLs to understand server response patterns
  - Fingerprints technologies and frameworks
  - Identifies security headers and potential weaknesses
  - Maps parameter behavior and response characteristics

- **Vulnerability Detection**:
  - SQL Injection (Error-based, Boolean-based, Time-based)
  - Insecure Direct Object Reference (IDOR)
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Insecure Deserialization
  - Server-Side Template Injection

- **Automated Enumeration**:
  - Intelligently iterates over parameter values
  - Identifies unique responses and patterns
  - Maps accessible resources
  - Discovers hidden parameters and endpoints

- **Data Extraction**:
  - Extracts sensitive information (emails, phone numbers, API keys)
  - Leverages detected vulnerabilities to access protected data
  - Structures and categorizes extracted information
  - Identifies potential PII and security credentials

- **Real-time Data Retrieval**:
  - Connects to RESTful APIs for real-time security intelligence
  - Establishes WebSocket connections for streaming data
  - Directly queries databases for up-to-date information
  - Monitors log files for security events
  - Processes and analyzes data in real-time

- **Advanced HTTP Client**:
  - HTTP/2 support for faster connections
  - WebSocket and Server-Sent Events (SSE) support
  - Streaming capabilities for large responses
  - Automatic retry and connection pooling
  - Comprehensive caching mechanisms

- **Comprehensive Reporting**:
  - Multiple output formats (JSON, CSV, HTML, SQLite)
  - Detailed vulnerability descriptions and evidence
  - Data visualization and relationship mapping
  - Remediation recommendations
  - Real-time monitoring dashboards

## 📋 Requirements

- Python 3.8+
- Required packages (see requirements.txt)
- Internet connection for web requests
- Permissions to test the target (important!)

## 🔧 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/xploit.git
cd xploit

# Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

### Using pip (if published)

```bash
pip install xploit
```

## 🚀 Usage

XPLOIT now supports two operation modes:
1. **Standard Mode**: For vulnerability scanning and data extraction
2. **Real-time Mode**: For real-time data retrieval from various sources

### Standard Mode (Vulnerability Scanning)

```bash
python -m xploit.main standard --url "https://example.com/page.php?id=123" --param "id"
```

### Real-time Mode (Data Retrieval)

```bash
# Setup real-time capabilities first
python setup_realtime.py --all

# Use real-time mode with a specific API
python -m xploit.main realtime --api shodan --api-endpoint "/shodan/host/search" --api-params '{"query": "apache"}'

# Monitor real-time data from all configured sources
python -m xploit.main realtime --all
```

### Command Line Options

#### Standard Mode Options

```
usage: xploit.main standard [-h] --url URL [--param PARAM] [--threads THREADS] [--delay DELAY]
                           [--output OUTPUT] [--format {json,csv,html,sqlite}] [--verbose]
                           [--quiet] [--no-color] [--sqli] [--idor]
                           [--idor-range IDOR_RANGE] [--timeout TIMEOUT]
                           [--user-agent USER_AGENT] [--cookies COOKIES] [--headers HEADERS]
                           [--proxy PROXY] [--auth AUTH]

options:
  -h, --help            show this help message and exit
  --url URL, -u URL     Target URL with parameter
  --param PARAM, -p PARAM
                        Parameter to test (default: auto-detect)
  --threads THREADS, -t THREADS
                        Number of threads (default: 5)
  --delay DELAY, -d DELAY
                        Delay between requests in seconds (default: 0.5)
  --output OUTPUT, -o OUTPUT
                        Output file for results
  --format {json,csv,html,sqlite}, -f {json,csv,html,sqlite}
                        Output format (default: json)
  --verbose, -v         Increase verbosity
  --quiet, -q           Suppress normal output
  --no-color            Disable color output

Testing Options:
  --sqli                Test for SQL injection
  --idor                Test for IDOR vulnerabilities
  --idor-range IDOR_RANGE
                        Range to test for IDOR (+/- from current ID, default: 100)

Advanced Options:
  --timeout TIMEOUT     Request timeout in seconds (default: 30)
  --user-agent USER_AGENT
                        Custom User-Agent string
  --cookies COOKIES     Cookies to include with requests (format: name=value; name2=value2)
  --headers HEADERS     Custom headers (format: header1:value1;header2:value2)
  --proxy PROXY         Proxy URL (e.g., http://127.0.0.1:8080)
  --auth AUTH           Basic authentication (username:password)
```

#### Real-time Mode Options

```
usage: xploit.main realtime [-h] [--config CONFIG] [--output OUTPUT]
                           [--format {json,csv,sqlite}] [--verbose] [--quiet]
                           [--no-color] [--api API] [--websocket WEBSOCKET]
                           [--database DATABASE] [--log LOG] [--all]
                           [--api-endpoint API_ENDPOINT]
                           [--api-method {GET,POST,PUT,DELETE}]
                           [--api-params API_PARAMS] [--api-data API_DATA]
                           [--duration DURATION] [--buffer-size BUFFER_SIZE]

options:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Path to the configuration file (default: config/realtime.yaml)
  --output OUTPUT, -o OUTPUT
                        Output file for results
  --format {json,csv,sqlite}, -f {json,csv,sqlite}
                        Output format (default: json)
  --verbose, -v         Increase verbosity
  --quiet, -q           Suppress normal output
  --no-color            Disable color output

Data Source Options:
  --api API             API name to use from configuration
  --websocket WEBSOCKET
                        WebSocket name to use from configuration
  --database DATABASE   Database name to use from configuration
  --log LOG             Log name to use from configuration
  --all                 Use all configured data sources

API Options:
  --api-endpoint API_ENDPOINT
                        API endpoint to query
  --api-method {GET,POST,PUT,DELETE}
                        API method (default: GET)
  --api-params API_PARAMS
                        API query parameters (JSON string)
  --api-data API_DATA   API request data (JSON string)

Runtime Options:
  --duration DURATION   Duration to run in seconds (0 = indefinite)
  --buffer-size BUFFER_SIZE
                        Maximum number of data points to keep in memory (default: 100)
```

### Examples

#### Standard Mode Examples

##### Basic Scan
```bash
python -m xploit.main standard --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --param "cat"
```

##### Verbose Output with Custom Threads and Delay
```bash
python -m xploit.main standard --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --param "cat" --threads 10 --delay 1 --verbose
```

##### Save Results to File
```bash
python -m xploit.main standard --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --param "cat" --output results.json
```

##### Using a Proxy (e.g., Burp Suite)
```bash
python -m xploit.main standard --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --param "cat" --proxy "http://127.0.0.1:8080"
```

##### With Authentication and Custom Headers
```bash
python -m xploit.main standard --url "https://example.com/api/users?id=123" --param "id" --auth "username:password" --headers "X-API-Key:abcdef123456;Content-Type:application/json"
```

#### Real-time Mode Examples

##### Query a Security API
```bash
python -m xploit.main realtime --api shodan --api-endpoint "/shodan/host/search" --api-params '{"query": "apache"}'
```

##### Monitor a Database for Changes
```bash
python -m xploit.main realtime --database local_results
```

##### Connect to a WebSocket for Real-time Updates
```bash
python -m xploit.main realtime --websocket threatstream
```

##### Monitor All Data Sources for 1 Hour
```bash
python -m xploit.main realtime --all --duration 3600 --output realtime_data.json
```

##### Custom Configuration File
```bash
python -m xploit.main realtime --config my_config.yaml --all
```

## 📊 Output Example

```json
{
  "target_url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
  "target_parameter": "cat",
  "base_value": "1",
  "scan_summary": {
    "start_time": 1621234567.89,
    "end_time": 1621234589.12,
    "duration": 21.23,
    "requests_made": 156
  },
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "param": "cat",
      "payload": "1' OR '1'='1",
      "url": "http://testphp.vulnweb.com/listproducts.php?cat=1' OR '1'='1",
      "status_code": 200,
      "confidence": "high",
      "description": "SQL injection vulnerability detected",
      "evidence": "Error: You have an error in your SQL syntax"
    }
  ],
  "extracted_data": {
    "base_data": {
      "emails": ["admin@example.com"],
      "phone_numbers": ["+1-555-123-4567"],
      "credit_cards": [],
      "api_keys": [],
      "tokens": []
    }
  }
}
```

## 🧪 Testing

XPLOIT includes a comprehensive test suite to ensure functionality and reliability:

```bash
# Run all tests
python -m unittest discover

# Run specific test modules
python -m unittest xploit.tests.test_modules
```

## 📝 Module Structure

- **Reconnaissance**: Analyzes the target URL and parameter to gather information
- **Vulnerability Detector**: Tests for various vulnerabilities using the gathered information
- **Enumerator**: Enumerates resources and data based on detected vulnerabilities
- **Data Extractor**: Extracts sensitive information from the target
- **Real-time Data Retriever**: Connects to various data sources for real-time information
- **Advanced HTTP Client**: Provides enhanced HTTP capabilities including HTTP/2 and WebSockets

## 🔄 Real-time Data Retrieval

The real-time data retrieval capabilities allow you to connect to various data sources to get up-to-date information:

### Supported Data Sources

- **RESTful APIs**: Connect to security intelligence APIs like Shodan, VirusTotal, and SecurityTrails
- **WebSockets**: Establish real-time connections to streaming data sources
- **Databases**: Directly query databases for the latest information
- **Log Files**: Monitor log files for security events and patterns

### Configuration

Real-time data sources are configured in the `config/realtime.yaml` file:

```yaml
# API endpoints for polling
apis:
  - name: "shodan"
    url: "https://api.shodan.io"
    method: "GET"
    headers:
      User-Agent: "XPLOIT Security Scanner"
    params:
      key: "YOUR_API_KEY"  # Replace with your actual API key
    interval: 300  # 5 minutes

# WebSocket connections for real-time data
websockets:
  - name: "threatstream"
    url: "wss://api.threatstream.com/ws"
    headers:
      User-Agent: "XPLOIT Security Scanner"
    auth:
      username: "YOUR_USERNAME"  # Replace with your actual username
      api_key: "YOUR_API_KEY"    # Replace with your actual API key

# Database connections for direct data access
databases:
  - name: "local_results"
    type: "sqlite"
    database: "data/output/results.db"
    query: "SELECT * FROM vulnerabilities ORDER BY vuln_id DESC LIMIT 10"
    interval: 60  # 1 minute

# Log files to monitor
logs:
  - name: "access_log"
    path: "/var/log/apache2/access.log"
    patterns:
      - "(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+).*\\[(?P<timestamp>.*?)\\]\\s+\"(?P<method>\\w+)\\s+(?P<url>.*?)\\s+HTTP.*?\"\\s+(?P<status>\\d+)"
```

### Setup

To set up the real-time data retrieval capabilities, run the setup script:

```bash
python setup_realtime.py --all
```

This will install all the required dependencies and create a default configuration file if one doesn't exist.

## 🔒 Security Considerations

- Always ensure you have proper authorization before testing any website or application
- Use appropriate delays between requests to avoid overwhelming the target server
- Consider using a proxy for more controlled testing
- Be mindful of sensitive data discovered during testing

## 🛡️ Ethical Usage Guidelines

XPLOIT is designed for ethical security testing only. Misuse of this tool may violate laws and regulations. Users are responsible for ensuring they have proper authorization before conducting any security testing.

Recommended ethical practices:
- Obtain written permission before testing
- Respect scope limitations
- Report vulnerabilities responsibly
- Avoid excessive testing that could impact service availability
- Handle discovered data with appropriate confidentiality

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📧 Contact

Project Link: [https://github.com/yourusername/xploit](https://github.com/yourusername/xploit)

---

⚠️ **Disclaimer**: This tool is designed for ethical security testing only. Always ensure you have proper authorization before testing any website or application. Unauthorized scanning may be illegal and unethical.