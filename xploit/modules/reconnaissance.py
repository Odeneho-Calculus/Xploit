"""
xploit/modules/reconnaissance.py - Reconnaissance module for the XPLOIT tool

This module analyzes target URLs to understand server response patterns,
identify technologies, and gather information about the target.
"""

import re
import logging
import hashlib
import json
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import random

from xploit.utils.http_client import HttpClient
from xploit.utils.helpers import (
    normalize_html,
    extract_page_title,
    extract_forms,
    extract_links,
    replace_param_in_url,
    get_param_value_from_url,
    response_similarity
)
from xploit.core.parser import ResponseParser

logger = logging.getLogger("xploit.modules.reconnaissance")

class Reconnaissance:
    """Reconnaissance module for analyzing target URLs"""
    
    def __init__(
        self,
        http_client: HttpClient,
        target_url: str,
        target_param: str,
        max_tests: int = 20
    ):
        """
        Initialize the Reconnaissance module
        
        Args:
            http_client: HTTP client for making requests
            target_url: Target URL to analyze
            target_param: Target parameter to analyze
            max_tests: Maximum number of tests to perform
        """
        self.http_client = http_client
        self.target_url = target_url
        self.target_param = target_param
        self.max_tests = max_tests
        
        # Extract the base parameter value
        self.base_param_value = get_param_value_from_url(target_url, target_param)
        if not self.base_param_value:
            logger.warning(f"Could not extract value for parameter '{target_param}' from URL. Using default value '1'.")
            self.base_param_value = "1"
            # Update URL with the default value
            self.target_url = replace_param_in_url(target_url, target_param, self.base_param_value)
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze the target URL and parameter
        
        Returns:
            Dict containing reconnaissance results
        """
        logger.info(f"Starting reconnaissance on {self.target_url} (parameter: {self.target_param})")
        
        results = {
            "target_info": self._gather_target_info(),
            "parameter_analysis": self._analyze_parameter(),
            "fingerprints": self._create_fingerprints(),
            "technology_detection": self._detect_technologies(),
            "security_headers": self._check_security_headers()
        }
        
        logger.info(f"Reconnaissance completed")
        return results
    
    def _gather_target_info(self) -> Dict[str, Any]:
        """
        Gather basic information about the target
        
        Returns:
            Dict containing target information
        """
        parsed_url = urlparse(self.target_url)
        
        # Get the base response
        base_response = self.http_client.get(self.target_url)
        
        # Extract title
        title = extract_page_title(base_response["text"]) or "No title"
        
        # Extract forms
        forms = extract_forms(base_response["text"])
        
        # Extract links
        links = extract_links(base_response["text"], base_url=self.target_url)
        
        # Parse the response
        parser = ResponseParser(base_response, self.target_url)
        
        return {
            "domain": parsed_url.netloc,
            "scheme": parsed_url.scheme,
            "path": parsed_url.path,
            "title": title,
            "status_code": base_response["status_code"],
            "content_length": len(base_response["text"]),
            "content_type": base_response["headers"].get("Content-Type", ""),
            "server": base_response["headers"].get("Server", ""),
            "forms_count": len(forms),
            "links_count": len(links),
            "comments": len(parser.extract_comments()),
            "scripts": len(parser.extract_scripts()),
            "potential_endpoints": parser.extract_potential_endpoints()
        }
    
    def _analyze_parameter(self) -> Dict[str, Any]:
        """
        Analyze the target parameter
        
        Returns:
            Dict containing parameter analysis results
        """
        results = {
            "name": self.target_param,
            "base_value": self.base_param_value,
            "is_numeric": self.base_param_value.isdigit(),
            "tests": []
        }
        
        # Test different parameter values
        test_values = self._generate_test_values()
        
        for test_value, test_type in test_values:
            test_url = replace_param_in_url(self.target_url, self.target_param, test_value)
            test_response = self.http_client.get(test_url)
            
            # Get the base response for comparison
            base_response = self.http_client.get(self.target_url)
            
            # Calculate similarity
            similarity = response_similarity(base_response["text"], test_response["text"])
            
            # Extract title
            title = extract_page_title(test_response["text"]) or "No title"
            
            # Add test result
            results["tests"].append({
                "value": test_value,
                "type": test_type,
                "url": test_url,
                "status_code": test_response["status_code"],
                "content_length": len(test_response["text"]),
                "title": title,
                "similarity": similarity,
                "response_hash": hashlib.md5(test_response["text"].encode()).hexdigest()
            })
        
        # Analyze the results to determine parameter behavior
        results["behavior"] = self._determine_parameter_behavior(results["tests"])
        
        return results
    
    def _generate_test_values(self) -> List[Tuple[str, str]]:
        """
        Generate test values for the parameter
        
        Returns:
            List of tuples containing (test_value, test_type)
        """
        test_values = []
        
        # If the parameter value is numeric
        if self.base_param_value.isdigit():
            base_int = int(self.base_param_value)
            
            # Test adjacent values
            test_values.append((str(base_int - 1), "adjacent_lower"))
            test_values.append((str(base_int + 1), "adjacent_higher"))
            
            # Test zero
            test_values.append(("0", "zero"))
            
            # Test negative value
            test_values.append(("-1", "negative"))
            
            # Test large value
            test_values.append(("999999", "large_number"))
            
            # Test non-numeric value
            test_values.append(("abc", "non_numeric"))
            
        else:
            # Test empty value
            test_values.append(("", "empty"))
            
            # Test numeric value
            test_values.append(("123", "numeric"))
            
            # Test special characters
            test_values.append(("test'", "single_quote"))
            test_values.append(('test"', "double_quote"))
            test_values.append(("test<>", "angle_brackets"))
            
        # Common test values for all types
        test_values.extend([
            (self.base_param_value + "'", "sql_quote"),
            (self.base_param_value + " OR 1=1", "sql_or"),
            (self.base_param_value + " AND 1=1", "sql_and"),
            (self.base_param_value + " UNION SELECT 1,2,3", "sql_union"),
            ("../../../etc/passwd", "path_traversal"),
            ("<script>alert(1)</script>", "xss"),
            (self.base_param_value + "%00", "null_byte"),
            (self.base_param_value + "/**/", "comment")
        ])
        
        # Limit the number of tests
        if len(test_values) > self.max_tests:
            # Randomly select a subset of tests
            random.shuffle(test_values)
            test_values = test_values[:self.max_tests]
        
        return test_values
    
    def _determine_parameter_behavior(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Determine the behavior of the parameter based on test results
        
        Args:
            tests: List of test results
            
        Returns:
            Dict containing parameter behavior analysis
        """
        behavior = {
            "appears_sequential": False,
            "appears_sensitive_to_type": False,
            "appears_vulnerable_to_injection": False,
            "response_variance": 0.0,
            "status_code_changes": False,
            "title_changes": False
        }
        
        # Check for sequential behavior (numeric parameters)
        if any(test["type"] == "adjacent_lower" for test in tests) and any(test["type"] == "adjacent_higher" for test in tests):
            adjacent_lower = next(test for test in tests if test["type"] == "adjacent_lower")
            adjacent_higher = next(test for test in tests if test["type"] == "adjacent_higher")
            
            # If the responses are different, it might be sequential
            if adjacent_lower["response_hash"] != adjacent_higher["response_hash"]:
                behavior["appears_sequential"] = True
        
        # Check for type sensitivity
        if any(test["type"] == "non_numeric" for test in tests):
            non_numeric_test = next(test for test in tests if test["type"] == "non_numeric")
            
            # If the response is significantly different, it might be sensitive to type
            if non_numeric_test["similarity"] < 0.8:
                behavior["appears_sensitive_to_type"] = True
        
        # Check for potential injection vulnerabilities
        injection_tests = [test for test in tests if test["type"] in ["sql_quote", "sql_or", "sql_and", "sql_union", "path_traversal", "xss"]]
        for test in injection_tests:
            # If any injection test causes a significant change in response
            if test["similarity"] < 0.7:
                behavior["appears_vulnerable_to_injection"] = True
                break
        
        # Calculate response variance
        similarities = [test["similarity"] for test in tests]
        if similarities:
            behavior["response_variance"] = 1.0 - (sum(similarities) / len(similarities))
        
        # Check for status code changes
        status_codes = set(test["status_code"] for test in tests)
        behavior["status_code_changes"] = len(status_codes) > 1
        
        # Check for title changes
        titles = set(test["title"] for test in tests)
        behavior["title_changes"] = len(titles) > 1
        
        return behavior
    
    def _create_fingerprints(self) -> Dict[str, Any]:
        """
        Create fingerprints of the target for later comparison
        
        Returns:
            Dict containing fingerprints
        """
        # Get the base response
        base_response = self.http_client.get(self.target_url)
        
        # Create fingerprints
        fingerprints = {
            "base_response": {
                "status_code": base_response["status_code"],
                "headers": base_response["headers"],
                "text": base_response["text"],
                "content_length": len(base_response["text"]),
                "hash": hashlib.md5(base_response["text"].encode()).hexdigest()
            },
            "error_patterns": self._identify_error_patterns()
        }
        
        return fingerprints
    
    def _identify_error_patterns(self) -> List[Dict[str, Any]]:
        """
        Identify error patterns in responses
        
        Returns:
            List of error patterns
        """
        error_patterns = []
        
        # Test with invalid values to trigger errors
        error_test_values = [
            ("'", "SQL error"),
            ("\\", "Backslash error"),
            ("<script>", "XSS/HTML error"),
            ("../", "Path traversal error"),
            ("undefined", "Undefined value error"),
            ("null", "Null value error"),
            ("NaN", "Not a number error")
        ]
        
        for test_value, error_type in error_test_values:
            test_url = replace_param_in_url(self.target_url, self.target_param, test_value)
            test_response = self.http_client.get(test_url)
            
            # Parse the response for errors
            parser = ResponseParser(test_response, test_url)
            errors = parser.extract_error_messages()
            
            if errors:
                error_patterns.append({
                    "test_value": test_value,
                    "error_type": error_type,
                    "status_code": test_response["status_code"],
                    "errors": errors
                })
        
        return error_patterns
    
    def _detect_technologies(self) -> Dict[str, Any]:
        """
        Detect technologies used by the target
        
        Returns:
            Dict containing detected technologies
        """
        # Get the base response
        base_response = self.http_client.get(self.target_url)
        
        technologies = {
            "server": base_response["headers"].get("Server", "Unknown"),
            "frameworks": [],
            "cms": None,
            "programming_language": None,
            "javascript_libraries": []
        }
        
        # Check for common frameworks and technologies in response
        html = base_response["text"]
        
        # Check for JavaScript libraries
        js_libraries = [
            ("jQuery", r'jquery[.-](\d+\.\d+\.\d+)'),
            ("React", r'react[.-](\d+\.\d+\.\d+)'),
            ("Angular", r'angular[.-](\d+\.\d+\.\d+)'),
            ("Vue.js", r'vue[.-](\d+\.\d+\.\d+)'),
            ("Bootstrap", r'bootstrap[.-](\d+\.\d+\.\d+)'),
            ("Lodash", r'lodash[.-](\d+\.\d+\.\d+)'),
            ("Moment.js", r'moment[.-](\d+\.\d+\.\d+)')
        ]
        
        for lib_name, lib_pattern in js_libraries:
            if re.search(lib_pattern, html, re.IGNORECASE):
                match = re.search(lib_pattern, html, re.IGNORECASE)
                version = match.group(1) if match else "Unknown"
                technologies["javascript_libraries"].append({
                    "name": lib_name,
                    "version": version
                })
        
        # Check for common CMS
        cms_patterns = [
            ("WordPress", r'wp-content|wordpress|wp-includes'),
            ("Joomla", r'joomla|com_content|com_users'),
            ("Drupal", r'drupal|sites/all|sites/default'),
            ("Magento", r'magento|skin/frontend'),
            ("Shopify", r'shopify|cdn.shopify.com'),
            ("Wix", r'wix.com|wixsite.com')
        ]
        
        for cms_name, cms_pattern in cms_patterns:
            if re.search(cms_pattern, html, re.IGNORECASE):
                technologies["cms"] = cms_name
                break
        
        # Check for programming languages
        lang_patterns = [
            ("PHP", r'php|laravel|symfony|codeigniter'),
            ("ASP.NET", r'asp.net|__viewstate|__VIEWSTATE'),
            ("Java", r'jsessionid|java|servlet'),
            ("Python", r'python|django|flask|wsgi'),
            ("Ruby", r'ruby|rails|rack'),
            ("Node.js", r'node|express|npm')
        ]
        
        for lang_name, lang_pattern in lang_patterns:
            if re.search(lang_pattern, html, re.IGNORECASE) or re.search(lang_pattern, str(base_response["headers"]), re.IGNORECASE):
                technologies["programming_language"] = lang_name
                break
        
        # Check for web frameworks
        framework_patterns = [
            ("Laravel", r'laravel'),
            ("Django", r'django'),
            ("Ruby on Rails", r'rails'),
            ("Express", r'express'),
            ("Flask", r'flask'),
            ("Spring", r'spring'),
            ("ASP.NET MVC", r'asp.net mvc|__requestverificationtoken'),
            ("Angular", r'ng-|angular'),
            ("React", r'react|reactjs'),
            ("Vue", r'vue|vuejs')
        ]
        
        for framework_name, framework_pattern in framework_patterns:
            if re.search(framework_pattern, html, re.IGNORECASE):
                technologies["frameworks"].append(framework_name)
        
        return technologies
    
    def _check_security_headers(self) -> Dict[str, Any]:
        """
        Check for security headers in the response
        
        Returns:
            Dict containing security header analysis
        """
        # Get the base response
        base_response = self.http_client.get(self.target_url)
        headers = base_response["headers"]
        
        security_headers = {
            "present": [],
            "missing": [],
            "analysis": {}
        }
        
        # List of important security headers
        important_headers = [
            "Content-Security-Policy",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Feature-Policy",
            "Permissions-Policy"
        ]
        
        # Check which headers are present and which are missing
        for header in important_headers:
            if header in headers:
                security_headers["present"].append(header)
                security_headers["analysis"][header] = {
                    "value": headers[header],
                    "effective": True  # Assume it's effective by default
                }
            else:
                security_headers["missing"].append(header)
        
        # Analyze the effectiveness of present headers
        if "X-XSS-Protection" in security_headers["present"]:
            value = headers["X-XSS-Protection"]
            security_headers["analysis"]["X-XSS-Protection"]["effective"] = "1; mode=block" in value
        
        if "X-Frame-Options" in security_headers["present"]:
            value = headers["X-Frame-Options"].upper()
            security_headers["analysis"]["X-Frame-Options"]["effective"] = value in ["DENY", "SAMEORIGIN"]
        
        if "Content-Security-Policy" in security_headers["present"]:
            value = headers["Content-Security-Policy"]
            # Check if CSP has unsafe-inline or unsafe-eval
            has_unsafe = "unsafe-inline" in value or "unsafe-eval" in value
            security_headers["analysis"]["Content-Security-Policy"]["effective"] = not has_unsafe
        
        # Calculate overall security score (0-100)
        total_headers = len(important_headers)
        present_headers = len(security_headers["present"])
        effective_headers = sum(1 for h in security_headers["analysis"].values() if h["effective"])
        
        security_headers["score"] = int((effective_headers / total_headers) * 100)
        
        return security_headers