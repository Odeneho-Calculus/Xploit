"""
xploit/modules/enumerator.py - Enumerator module for the XPLOIT tool
"""

import re
import time
import logging
import hashlib
import concurrent.futures
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
from urllib.parse import urlparse, urljoin

from xploit.utils.http_client import HttpClient
from xploit.utils.helpers import (
    normalize_html,
    extract_page_title,
    replace_param_in_url,
    get_param_value_from_url,
    response_similarity
)

logger = logging.getLogger("xploit.modules.enumerator")

class Enumerator:
    """Enumerator module for enumerating resources and data"""
    
    def __init__(
        self,
        http_client: HttpClient,
        target_url: str,
        target_param: str,
        param_value: str,
        threads: int = 5,
        idor_range: int = 100,
        max_requests: int = 1000
    ):
        """
        Initialize the Enumerator module
        
        Args:
            http_client: HTTP client for making requests
            target_url: Target URL to analyze
            target_param: Target parameter to analyze
            param_value: Current value of the target parameter
            threads: Number of threads to use for concurrent testing
            idor_range: Range of IDs to enumerate for IDOR
            max_requests: Maximum number of requests to make
        """
        self.http_client = http_client
        self.target_url = target_url
        self.target_param = target_param
        self.param_value = param_value
        self.threads = threads
        self.idor_range = idor_range
        self.max_requests = max_requests
        
        # Get the base response
        self.base_response = self.http_client.get(target_url)
        self.base_hash = hashlib.md5(self.base_response["text"].encode()).hexdigest()
    
    def enumerate(self) -> Dict[str, Any]:
        """
        Enumerate resources and data
        
        Returns:
            Dict containing enumeration results
        """
        logger.info(f"Starting enumeration on {self.target_url} (parameter: {self.target_param})")
        
        results = {}
        
        # Enumerate IDs if the parameter value is numeric
        if self.param_value.isdigit():
            idor_results = self._enumerate_idor()
            results.update(idor_results)
        
        # Enumerate common parameters
        param_results = self._enumerate_parameters()
        results.update(param_results)
        
        # Enumerate directories
        dir_results = self._enumerate_directories()
        results.update(dir_results)
        
        logger.info(f"Enumeration completed")
        return results
    
    def _enumerate_idor(self) -> Dict[str, Any]:
        """
        Enumerate IDs for IDOR (Insecure Direct Object Reference)
        
        Returns:
            Dict containing IDOR enumeration results
        """
        logger.info(f"Enumerating IDs for IDOR (range: {self.idor_range})")
        
        results = {
            "idor": {
                "valid_ids": [],
                "unique_responses": [],
                "response_clusters": {}
            }
        }
        
        # Generate IDs to test
        current_id = int(self.param_value)
        start_id = max(1, current_id - self.idor_range // 2)
        end_id = start_id + self.idor_range
        
        test_ids = list(range(start_id, end_id))
        
        # Limit the number of requests
        if len(test_ids) > self.max_requests:
            logger.warning(f"Too many IDs to test ({len(test_ids)}), limiting to {self.max_requests}")
            test_ids = test_ids[:self.max_requests]
        
        # Store unique responses by hash
        unique_responses = {}
        response_clusters = defaultdict(list)
        
        # Test each ID
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_id = {
                executor.submit(self._test_id, test_id): test_id
                for test_id in test_ids
            }
            
            for future in concurrent.futures.as_completed(future_to_id):
                test_id = future_to_id[future]
                try:
                    response_data = future.result()
                    if response_data:
                        # Add to valid IDs
                        results["idor"]["valid_ids"].append(test_id)
                        
                        # Add to unique responses if not already present
                        response_hash = response_data["response_hash"]
                        if response_hash not in unique_responses:
                            unique_responses[response_hash] = response_data
                            
                        # Add to response clusters
                        response_clusters[response_hash].append(test_id)
                except Exception as e:
                    logger.error(f"Error testing ID {test_id}: {str(e)}")
        
        # Convert unique responses to list
        results["idor"]["unique_responses"] = list(unique_responses.values())
        
        # Convert response clusters to dict with hash as key and IDs as value
        results["idor"]["response_clusters"] = {
            hash_val: {
                "ids": id_list,
                "count": len(id_list),
                "sample_url": replace_param_in_url(self.target_url, self.target_param, str(id_list[0]))
            }
            for hash_val, id_list in response_clusters.items()
        }
        
        logger.info(f"Found {len(results['idor']['valid_ids'])} valid IDs and {len(results['idor']['unique_responses'])} unique responses")
        return results
    
    def _test_id(self, test_id: int) -> Optional[Dict[str, Any]]:
        """
        Test an ID for IDOR
        
        Args:
            test_id: The ID to test
            
        Returns:
            Dict containing response data if the ID is valid, None otherwise
        """
        test_url = replace_param_in_url(self.target_url, self.target_param, str(test_id))
        test_response = self.http_client.get(test_url)
        
        # Check if the response is successful
        if test_response["status_code"] == 200:
            response_hash = hashlib.md5(test_response["text"].encode()).hexdigest()
            
            # Extract title
            title = extract_page_title(test_response["text"]) or "No title"
            
            return {
                "id": test_id,
                "url": test_url,
                "status_code": test_response["status_code"],
                "content_length": len(test_response["text"]),
                "response_hash": response_hash,
                "title": title
            }
        
        return None
    
    def _enumerate_parameters(self) -> Dict[str, Any]:
        """
        Enumerate common parameters
        
        Returns:
            Dict containing parameter enumeration results
        """
        logger.info("Enumerating common parameters")
        
        results = {
            "parameters": {
                "valid_params": [],
                "unique_responses": []
            }
        }
        
        # Common parameters to test
        common_params = [
            "id", "user_id", "uid", "user", "username", "name", "email", "page", "action",
            "file", "filename", "path", "dir", "directory", "type", "mode", "view", "query",
            "search", "q", "s", "keyword", "keywords", "year", "month", "day", "date",
            "category", "cat", "filter", "order", "sort", "limit", "offset", "start", "end",
            "price", "cost", "val", "value", "data", "debug", "test", "demo", "admin"
        ]
        
        # Limit the number of parameters to test
        if len(common_params) > self.max_requests:
            logger.warning(f"Too many parameters to test ({len(common_params)}), limiting to {self.max_requests}")
            common_params = common_params[:self.max_requests]
        
        # Store unique responses by hash
        unique_responses = {}
        
        # Test each parameter
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_param = {
                executor.submit(self._test_parameter, param): param
                for param in common_params
                if param != self.target_param  # Skip the target parameter
            }
            
            for future in concurrent.futures.as_completed(future_to_param):
                param = future_to_param[future]
                try:
                    response_data = future.result()
                    if response_data:
                        # Add to valid parameters
                        results["parameters"]["valid_params"].append(param)
                        
                        # Add to unique responses if not already present
                        response_hash = response_data["response_hash"]
                        if response_hash not in unique_responses:
                            unique_responses[response_hash] = response_data
                except Exception as e:
                    logger.error(f"Error testing parameter {param}: {str(e)}")
        
        # Convert unique responses to list
        results["parameters"]["unique_responses"] = list(unique_responses.values())
        
        logger.info(f"Found {len(results['parameters']['valid_params'])} valid parameters and {len(results['parameters']['unique_responses'])} unique responses")
        return results
    
    def _test_parameter(self, param: str) -> Optional[Dict[str, Any]]:
        """
        Test a parameter
        
        Args:
            param: The parameter to test
            
        Returns:
            Dict containing response data if the parameter is valid, None otherwise
        """
        # Add the parameter to the URL
        test_url = f"{self.target_url}&{param}=1"
        if "?" not in test_url:
            test_url = test_url.replace("&", "?", 1)
        
        test_response = self.http_client.get(test_url)
        
        # Check if the response is successful and different from the base response
        if test_response["status_code"] == 200:
            response_hash = hashlib.md5(test_response["text"].encode()).hexdigest()
            
            if response_hash != self.base_hash:
                # Extract title
                title = extract_page_title(test_response["text"]) or "No title"
                
                return {
                    "param": param,
                    "url": test_url,
                    "status_code": test_response["status_code"],
                    "content_length": len(test_response["text"]),
                    "response_hash": response_hash,
                    "title": title
                }
        
        return None
    
    def _enumerate_directories(self) -> Dict[str, Any]:
        """
        Enumerate common directories
        
        Returns:
            Dict containing directory enumeration results
        """
        logger.info("Enumerating common directories")
        
        results = {
            "directories": {
                "valid_dirs": [],
                "unique_responses": []
            }
        }
        
        # Parse the base URL to get the domain
        parsed_url = urlparse(self.target_url)
        base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Common directories to test
        common_dirs = [
            "/admin", "/administrator", "/login", "/wp-admin", "/wp-login.php", "/admin.php",
            "/user", "/users", "/account", "/accounts", "/profile", "/dashboard", "/cp", "/cpanel",
            "/portal", "/api", "/api/v1", "/api/v2", "/docs", "/documentation", "/swagger",
            "/backup", "/backups", "/db", "/database", "/logs", "/log", "/tmp", "/temp",
            "/upload", "/uploads", "/files", "/file", "/images", "/img", "/css", "/js",
            "/static", "/assets", "/media", "/public", "/private", "/secret", "/config",
            "/settings", "/setup", "/install", "/test", "/demo", "/dev", "/development",
            "/staging", "/stage", "/prod", "/production", "/old", "/new", "/beta"
        ]
        
        # Limit the number of directories to test
        if len(common_dirs) > self.max_requests:
            logger.warning(f"Too many directories to test ({len(common_dirs)}), limiting to {self.max_requests}")
            common_dirs = common_dirs[:self.max_requests]
        
        # Store unique responses by hash
        unique_responses = {}
        
        # Test each directory
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_dir = {
                executor.submit(self._test_directory, base_domain, dir_path): dir_path
                for dir_path in common_dirs
            }
            
            for future in concurrent.futures.as_completed(future_to_dir):
                dir_path = future_to_dir[future]
                try:
                    response_data = future.result()
                    if response_data:
                        # Add to valid directories
                        results["directories"]["valid_dirs"].append(dir_path)
                        
                        # Add to unique responses if not already present
                        response_hash = response_data["response_hash"]
                        if response_hash not in unique_responses:
                            unique_responses[response_hash] = response_data
                except Exception as e:
                    logger.error(f"Error testing directory {dir_path}: {str(e)}")
        
        # Convert unique responses to list
        results["directories"]["unique_responses"] = list(unique_responses.values())
        
        logger.info(f"Found {len(results['directories']['valid_dirs'])} valid directories and {len(results['directories']['unique_responses'])} unique responses")
        return results
    
    def _test_directory(self, base_domain: str, dir_path: str) -> Optional[Dict[str, Any]]:
        """
        Test a directory
        
        Args:
            base_domain: The base domain
            dir_path: The directory path to test
            
        Returns:
            Dict containing response data if the directory is valid, None otherwise
        """
        test_url = f"{base_domain}{dir_path}"
        test_response = self.http_client.get(test_url)
        
        # Check if the response is successful (200, 301, 302, 307, 308)
        valid_status_codes = [200, 301, 302, 307, 308]
        if test_response["status_code"] in valid_status_codes:
            response_hash = hashlib.md5(test_response["text"].encode()).hexdigest()
            
            # Extract title
            title = extract_page_title(test_response["text"]) or "No title"
            
            return {
                "dir": dir_path,
                "url": test_url,
                "status_code": test_response["status_code"],
                "content_length": len(test_response["text"]),
                "response_hash": response_hash,
                "title": title
            }
        
        return None