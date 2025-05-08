"""
xploit/core/engine.py - Main engine that orchestrates the exploitation process
"""

import logging
import json
import csv
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable

from xploit.modules.reconnaissance import Reconnaissance
from xploit.modules.vulnerability_detector import VulnerabilityDetector
from xploit.modules.enumerator import Enumerator
from xploit.modules.data_extractor import DataExtractor
from xploit.utils.http_client import HttpClient
from xploit.utils.helpers import (
    get_param_value_from_url, 
    replace_param_in_url,
    parse_headers_string,
    parse_cookies_string
)

logger = logging.getLogger("xploit.core.engine")

class XploitEngine:
    """Main engine class that coordinates all XPLOIT modules"""
    
    def __init__(
        self, 
        url: str, 
        param: str, 
        threads: int = 5, 
        delay: float = 0.5, 
        timeout: int = 30, 
        user_agent: Optional[str] = None, 
        cookies: Optional[str] = None, 
        headers: Optional[str] = None, 
        proxy: Optional[str] = None, 
        auth: Optional[str] = None,
        output_file: Optional[str] = None, 
        output_format: str = "json", 
        idor_range: int = 100
    ):
        """
        Initialize the XPLOIT engine
        
        Args:
            url: Target URL with parameter
            param: Parameter to test
            threads: Number of threads to use
            delay: Delay between requests
            timeout: Request timeout in seconds
            user_agent: Custom User-Agent
            cookies: Cookies to include (format: name=value; name2=value2)
            headers: Custom headers (format: header1:value1;header2:value2)
            proxy: Proxy URL
            auth: Basic authentication credentials (format: username:password)
            output_file: Output file for results
            output_format: Output format (json, csv, html, sqlite)
            idor_range: Range to test for IDOR vulnerabilities
        """
        self.url = url
        self.param = param
        self.threads = min(max(1, threads), 20)  # Limit threads between 1 and 20
        self.delay = delay
        self.timeout = timeout
        self.idor_range = idor_range
        
        # Parse custom headers
        custom_headers = parse_headers_string(headers) if headers else {}
        
        # Parse cookies
        parsed_cookies = parse_cookies_string(cookies) if cookies else {}
        
        # Parse basic auth
        auth_tuple = None
        if auth and ':' in auth:
            username, password = auth.split(':', 1)
            auth_tuple = (username, password)
        
        # Initialize HTTP client
        self.http_client = HttpClient(
            user_agent=user_agent,
            headers=custom_headers,
            cookies=parsed_cookies,
            proxy=proxy,
            auth=auth_tuple,
            timeout=timeout,
            delay=delay
        )
        
        # Output configuration
        self.output_file = output_file
        self.output_format = output_format.lower()
        
        # Extract base parameter value
        self.base_param_value = get_param_value_from_url(url, param)
        if not self.base_param_value:
            logger.warning(f"Could not extract value for parameter '{param}' from URL. Using default value '1'.")
            self.base_param_value = "1"
            # Update URL with the default value
            self.url = replace_param_in_url(url, param, self.base_param_value)
        
        # Initialize results
        self.results = {
            "target_url": url,
            "target_parameter": param,
            "base_value": self.base_param_value,
            "scan_summary": {
                "start_time": None,
                "end_time": None,
                "duration": None,
                "requests_made": 0
            }
        }
    
    def run(self, progress=None):
        """
        Run the XPLOIT engine
        
        Args:
            progress: Rich progress instance for progress reporting
            
        Returns:
            dict: Results of the scan
        """
        self.results["scan_summary"]["start_time"] = time.time()
        
        # Create tasks if progress reporting is enabled
        recon_task = progress.add_task("[cyan]Reconnaissance...", total=100) if progress else None
        vuln_task = progress.add_task("[yellow]Vulnerability Detection...", total=100, visible=False) if progress else None
        enum_task = progress.add_task("[green]Enumeration...", total=100, visible=False) if progress else None
        extract_task = progress.add_task("[magenta]Data Extraction...", total=100, visible=False) if progress else None
        
        try:
            # Step 1: Reconnaissance
            logger.info("Starting reconnaissance phase")
            recon = Reconnaissance(self.http_client, self.url, self.param)
            recon_results = recon.analyze()
            
            self.results["reconnaissance"] = recon_results
            logger.info(f"Reconnaissance complete")
            
            if progress:
                progress.update(recon_task, completed=100)
                progress.update(vuln_task, visible=True)
            
            # Step 2: Vulnerability Detection
            logger.info("Starting vulnerability detection phase")
            vuln_detector = VulnerabilityDetector(
                self.http_client, 
                self.url, 
                self.param, 
                self.base_param_value,
                recon_results,
                threads=self.threads
            )
            vuln_results = vuln_detector.detect_vulnerabilities()
            
            self.results["vulnerabilities"] = vuln_results
            logger.info(f"Vulnerability detection complete: {len(vuln_results)} potential vulnerabilities found")
            
            if progress:
                progress.update(vuln_task, completed=100)
                progress.update(enum_task, visible=True)
            
            # Step 3: Enumeration
            logger.info("Starting enumeration phase")
            enumerator = Enumerator(
                self.http_client, 
                self.url, 
                self.param, 
                self.base_param_value,
                threads=self.threads,
                idor_range=self.idor_range
            )
            enum_results = enumerator.enumerate()
            
            self.results["enumeration"] = enum_results
            logger.info(f"Enumeration complete")
            
            if progress:
                progress.update(enum_task, completed=100)
                progress.update(extract_task, visible=True)
            
            # Step 4: Data Extraction
            logger.info("Starting data extraction phase")
            data_extractor = DataExtractor(
                self.http_client,
                self.url,
                self.param,
                recon_results,
                vuln_results,
                threads=self.threads
            )
            extracted_data = data_extractor.extract_data()
            
            self.results["extracted_data"] = extracted_data
            logger.info(f"Data extraction complete")
            
            if progress:
                progress.update(extract_task, completed=100)
            
            # Update scan summary
            self.results["scan_summary"]["end_time"] = time.time()
            self.results["scan_summary"]["duration"] = self.results["scan_summary"]["end_time"] - self.results["scan_summary"]["start_time"]
            self.results["scan_summary"]["requests_made"] = self.http_client.request_count
            
            # Save results if output file is specified
            if self.output_file:
                self._save_results()
            
            return self.results
            
        except Exception as e:
            logger.exception("Error during scan execution:")
            if progress:
                for task_id in [recon_task, vuln_task, enum_task, extract_task]:
                    if task_id:
                        progress.update(task_id, description=f"[bold red]Error: {str(e)[:30]}...")
            
            # Update scan summary even in case of error
            self.results["scan_summary"]["end_time"] = time.time()
            self.results["scan_summary"]["duration"] = self.results["scan_summary"]["end_time"] - self.results["scan_summary"]["start_time"]
            self.results["scan_summary"]["requests_made"] = self.http_client.request_count
            self.results["error"] = str(e)
            
            # Try to save results even in case of error
            if self.output_file:
                self._save_results()
                
            raise
    
    def _save_results(self):
        """Save the results to the specified output file in the specified format"""
        try:
            output_path = Path(self.output_file)
            
            # Create directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save in the specified format
            if self.output_format == "json" or not output_path.suffix:
                if not output_path.suffix:
                    output_path = output_path.with_suffix(".json")
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2)
                    
            elif self.output_format == "csv":
                if not output_path.suffix:
                    output_path = output_path.with_suffix(".csv")
                
                # For CSV, we'll flatten the vulnerabilities for easier viewing
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    # Write headers
                    headers = ["type", "param", "payload", "url", "status_code", "confidence"]
                    writer.writerow(headers)
                    
                    # Write vulnerabilities
                    for vuln in self.results.get("vulnerabilities", []):
                        writer.writerow([
                            vuln.get("type", ""),
                            vuln.get("param", ""),
                            vuln.get("payload", ""),
                            vuln.get("url", ""),
                            vuln.get("status_code", ""),
                            vuln.get("confidence", "")
                        ])
                        
            elif self.output_format == "html":
                if not output_path.suffix:
                    output_path = output_path.with_suffix(".html")
                
                # Basic HTML report template
                html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>XPLOIT Scan Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .section {{ margin-bottom: 20px; }}
        .vuln {{ background-color: #ffecec; padding: 10px; border-left: 4px solid #ff0000; margin-bottom: 10px; }}
        .data-point {{ background-color: #f0f8ff; padding: 10px; border-left: 4px solid #0066cc; margin-bottom: 5px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .summary {{ background-color: #e6f7e6; padding: 15px; border-radius: 5px; }}
        pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>XPLOIT Scan Results</h1>
    
    <div class="section summary">
        <h2>Scan Summary</h2>
        <p><strong>Target URL:</strong> {self.url}</p>
        <p><strong>Target Parameter:</strong> {self.param}</p>
        <p><strong>Base Value:</strong> {self.base_param_value}</p>
        <p><strong>Duration:</strong> {self.results["scan_summary"]["duration"]:.2f} seconds</p>
        <p><strong>Requests Made:</strong> {self.results["scan_summary"]["requests_made"]}</p>
    </div>
    
    <div class="section">
        <h2>Vulnerabilities Found</h2>
        {"<p>No vulnerabilities detected.</p>" if not self.results.get("vulnerabilities") else ""}
"""
                
                # Add each vulnerability
                for i, vuln in enumerate(self.results.get("vulnerabilities", []), 1):
                    html_content += f"""
        <div class="vuln">
            <h3>{i}. {vuln.get("type", "Unknown")}</h3>
            <p><strong>Parameter:</strong> {vuln.get("param", "N/A")}</p>
            <p><strong>Payload:</strong> {vuln.get("payload", "N/A")}</p>
            <p><strong>URL:</strong> <a href="{vuln.get("url", "#")}" target="_blank">{vuln.get("url", "N/A")}</a></p>
            <p><strong>Status Code:</strong> {vuln.get("status_code", "N/A")}</p>
            <p><strong>Confidence:</strong> {vuln.get("confidence", "N/A")}</p>
        </div>
"""
                
                # Add extracted data section
                html_content += """
    </div>
    
    <div class="section">
        <h2>Extracted Data</h2>
"""
                
                # Check if there's any extracted data
                if not self.results.get("extracted_data"):
                    html_content += "        <p>No data extracted.</p>\n"
                else:
                    # Add data from different sources
                    for data_type, data_items in self.results.get("extracted_data", {}).items():
                        html_content += f"""
        <h3>{data_type.replace("_", " ").title()}</h3>
        <div class="data-container">
"""
                        
                        # Handle different data types differently
                        if isinstance(data_items, dict):
                            for key, value in data_items.items():
                                html_content += f"""
            <div class="data-point">
                <p><strong>{key}:</strong> {value}</p>
            </div>
"""
                        elif isinstance(data_items, list):
                            for item in data_items:
                                if isinstance(item, dict):
                                    html_content += f"""
            <div class="data-point">
"""
                                    for key, value in item.items():
                                        html_content += f"""
                <p><strong>{key}:</strong> {value}</p>
"""
                                    html_content += """
            </div>
"""
                                else:
                                    html_content += f"""
            <div class="data-point">
                <p>{item}</p>
            </div>
"""
                        
                        html_content += """
        </div>
"""
                
                # Close the HTML document
                html_content += """
    </div>
</body>
</html>
"""
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                    
            elif self.output_format == "sqlite":
                if not output_path.suffix:
                    output_path = output_path.with_suffix(".db")
                
                # Import sqlite3 here to avoid dependency if not used
                import sqlite3
                
                # Connect to the database
                conn = sqlite3.connect(str(output_path))
                cursor = conn.cursor()
                
                # Create tables
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_info (
                    id INTEGER PRIMARY KEY,
                    target_url TEXT,
                    target_parameter TEXT,
                    base_value TEXT,
                    start_time REAL,
                    end_time REAL,
                    duration REAL,
                    requests_made INTEGER
                )
                ''')
                
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY,
                    scan_id INTEGER,
                    type TEXT,
                    param TEXT,
                    payload TEXT,
                    url TEXT,
                    status_code INTEGER,
                    confidence TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_info (id)
                )
                ''')
                
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS extracted_data (
                    id INTEGER PRIMARY KEY,
                    scan_id INTEGER,
                    data_type TEXT,
                    data_key TEXT,
                    data_value TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_info (id)
                )
                ''')
                
                # Insert scan info
                cursor.execute('''
                INSERT INTO scan_info (
                    target_url, target_parameter, base_value, 
                    start_time, end_time, duration, requests_made
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    self.url, 
                    self.param, 
                    self.base_param_value,
                    self.results["scan_summary"]["start_time"],
                    self.results["scan_summary"]["end_time"],
                    self.results["scan_summary"]["duration"],
                    self.results["scan_summary"]["requests_made"]
                ))
                
                scan_id = cursor.lastrowid
                
                # Insert vulnerabilities
                for vuln in self.results.get("vulnerabilities", []):
                    cursor.execute('''
                    INSERT INTO vulnerabilities (
                        scan_id, type, param, payload, url, status_code, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        vuln.get("type", ""),
                        vuln.get("param", ""),
                        vuln.get("payload", ""),
                        vuln.get("url", ""),
                        vuln.get("status_code", 0),
                        vuln.get("confidence", "")
                    ))
                
                # Insert extracted data
                for data_type, data_items in self.results.get("extracted_data", {}).items():
                    if isinstance(data_items, dict):
                        for key, value in data_items.items():
                            cursor.execute('''
                            INSERT INTO extracted_data (
                                scan_id, data_type, data_key, data_value
                            ) VALUES (?, ?, ?, ?)
                            ''', (
                                scan_id,
                                data_type,
                                key,
                                str(value)
                            ))
                    elif isinstance(data_items, list):
                        for i, item in enumerate(data_items):
                            if isinstance(item, dict):
                                for key, value in item.items():
                                    cursor.execute('''
                                    INSERT INTO extracted_data (
                                        scan_id, data_type, data_key, data_value
                                    ) VALUES (?, ?, ?, ?)
                                    ''', (
                                        scan_id,
                                        data_type,
                                        f"{i}_{key}",
                                        str(value)
                                    ))
                            else:
                                cursor.execute('''
                                INSERT INTO extracted_data (
                                    scan_id, data_type, data_key, data_value
                                ) VALUES (?, ?, ?, ?)
                                ''', (
                                    scan_id,
                                    data_type,
                                    str(i),
                                    str(item)
                                ))
                
                # Commit and close
                conn.commit()
                conn.close()
            
            logger.info(f"Results saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
            raise