"""
xploit/utils/http_client.py - HTTP client for making requests to the target
"""

import time
import logging
import hashlib
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, Optional, Tuple, Union, List, Any

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from requests.structures import CaseInsensitiveDict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("xploit.utils.http_client")

class HttpClient:
    def __init__(
        self,
        user_agent: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: int = 30,
        delay: float = 0.5,
        max_retries: int = 3
    ):
        self.timeout = timeout
        self.delay = delay
        self.last_request_time = 0
        self.request_count = 0
        self.response_cache = {}
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
        ]
        default_user_agent = user_agent or random.choice(self.user_agents)
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504, 403, 408],
            allowed_methods=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"],
            respect_retry_after_header=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "User-Agent": default_user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        })
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if auth:
            self.session.auth = auth
            
    def _throttle_request(self) -> None:
        """
        Throttle requests to avoid overloading the server
        """
        if self.delay > 0:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self.last_request_time = time.time()
    
    def _process_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Process the response and return a standardized format
        
        Args:
            response: The requests.Response object
            
        Returns:
            Dict containing processed response data
        """
        return {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "text": response.text,
            "content": response.content,
            "cookies": dict(response.cookies),
            "elapsed": response.elapsed.total_seconds(),
            "is_redirect": response.is_redirect
        }
    
    def _get_cache_key(self, method: str, url: str, **kwargs) -> str:
        """
        Generate a cache key for the request
        
        Args:
            method: HTTP method
            url: URL
            **kwargs: Additional request parameters
            
        Returns:
            Cache key string
        """
        # Create a string representation of the request
        key_parts = [method.upper(), url]
        
        # Add other parameters that affect the request
        if "params" in kwargs and kwargs["params"]:
            key_parts.append(str(kwargs["params"]))
        if "data" in kwargs and kwargs["data"]:
            key_parts.append(str(kwargs["data"]))
        if "json" in kwargs and kwargs["json"]:
            key_parts.append(str(kwargs["json"]))
        if "headers" in kwargs and kwargs["headers"]:
            key_parts.append(str(kwargs["headers"]))
        
        # Generate a hash of the combined string
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make an HTTP request
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            files: Files to upload
            auth: Authentication credentials
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        method = method.upper()
        timeout = timeout or self.timeout
        
        # Check cache if enabled
        if use_cache:
            cache_key = self._get_cache_key(method, url, params=params, data=data, json=json, headers=headers)
            if cache_key in self.response_cache:
                logger.debug(f"Cache hit for {method} {url}")
                return self.response_cache[cache_key]
        
        # Throttle request if needed
        self._throttle_request()
        
        # Log the request
        logger.debug(f"Making {method} request to {url}")
        
        try:
            # Make the request
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                cookies=cookies,
                files=files,
                auth=auth,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=verify
            )
            
            # Process the response
            processed_response = self._process_response(response)
            
            # Cache the response if enabled
            if use_cache:
                self.response_cache[cache_key] = processed_response
            
            # Update request count
            self.request_count += 1
            
            return processed_response
            
        except Timeout as e:
            logger.error(f"Request timeout: {e}")
            return {
                "url": url,
                "status_code": 0,
                "headers": {},
                "text": f"Request timeout: {str(e)}",
                "content": b"",
                "cookies": {},
                "elapsed": 0,
                "is_redirect": False,
                "error": "timeout"
            }
        except ConnectionError as e:
            logger.error(f"Connection error: {e}")
            return {
                "url": url,
                "status_code": 0,
                "headers": {},
                "text": f"Connection error: {str(e)}",
                "content": b"",
                "cookies": {},
                "elapsed": 0,
                "is_redirect": False,
                "error": "connection"
            }
        except RequestException as e:
            logger.error(f"Request error: {e}")
            return {
                "url": url,
                "status_code": 0,
                "headers": {},
                "text": f"Request error: {str(e)}",
                "content": b"",
                "cookies": {},
                "elapsed": 0,
                "is_redirect": False,
                "error": "request"
            }
    
    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make a GET request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="GET",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def post(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = False
    ) -> Dict[str, Any]:
        """
        Make a POST request
        
        Args:
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            files: Files to upload
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="POST",
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            files=files,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def put(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = False
    ) -> Dict[str, Any]:
        """
        Make a PUT request
        
        Args:
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            files: Files to upload
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="PUT",
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            files=files,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def delete(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = False
    ) -> Dict[str, Any]:
        """
        Make a DELETE request
        
        Args:
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="DELETE",
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def head(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = False,
        verify: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make a HEAD request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="HEAD",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def options(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make an OPTIONS request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="OPTIONS",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def clear_cache(self) -> None:
        """
        Clear the response cache
        """
        self.response_cache = {}
        logger.debug("Response cache cleared")
    
    def rotate_user_agent(self) -> str:
        """
        Rotate the User-Agent header
        
        Returns:
            The new User-Agent string
        """
        new_user_agent = random.choice(self.user_agents)
        self.session.headers.update({"User-Agent": new_user_agent})
        logger.debug(f"Rotated User-Agent to: {new_user_agent}")
        return new_user_agent
            
    def _throttle_request(self) -> None:
        """
        Throttle requests to avoid overloading the server
        """
        if self.delay > 0:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self.last_request_time = time.time()
    
    def _process_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Process the response and return a standardized format
        
        Args:
            response: The requests.Response object
            
        Returns:
            Dict containing processed response data
        """
        return {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "text": response.text,
            "content": response.content,
            "cookies": dict(response.cookies),
            "elapsed": response.elapsed.total_seconds(),
            "is_redirect": response.is_redirect
        }
    
    def _get_cache_key(self, method: str, url: str, **kwargs) -> str:
        """
        Generate a cache key for the request
        
        Args:
            method: HTTP method
            url: URL
            **kwargs: Additional request parameters
            
        Returns:
            Cache key string
        """
        # Create a string representation of the request
        key_parts = [method.upper(), url]
        
        # Add other parameters that affect the request
        if "params" in kwargs and kwargs["params"]:
            key_parts.append(str(kwargs["params"]))
        if "data" in kwargs and kwargs["data"]:
            key_parts.append(str(kwargs["data"]))
        if "json" in kwargs and kwargs["json"]:
            key_parts.append(str(kwargs["json"]))
        if "headers" in kwargs and kwargs["headers"]:
            key_parts.append(str(kwargs["headers"]))
        
        # Generate a hash of the combined string
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make an HTTP request
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            files: Files to upload
            auth: Authentication credentials
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        method = method.upper()
        timeout = timeout or self.timeout
        
        # Check cache if enabled
        if use_cache:
            cache_key = self._get_cache_key(method, url, params=params, data=data, json=json, headers=headers)
            if cache_key in self.response_cache:
                logger.debug(f"Cache hit for {method} {url}")
                return self.response_cache[cache_key]
        
        # Throttle request if needed
        self._throttle_request()
        
        # Log the request
        logger.debug(f"Making {method} request to {url}")
        
        try:
            # Make the request
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                cookies=cookies,
                files=files,
                auth=auth,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=verify
            )
            
            # Process the response
            processed_response = self._process_response(response)
            
            # Cache the response if enabled
            if use_cache:
                self.response_cache[cache_key] = processed_response
            
            # Update request count
            self.request_count += 1
            
            return processed_response
            
        except Timeout as e:
            logger.error(f"Request timeout: {e}")
            return {
                "url": url,
                "status_code": 0,
                "headers": {},
                "text": f"Request timeout: {str(e)}",
                "content": b"",
                "cookies": {},
                "elapsed": 0,
                "is_redirect": False,
                "error": "timeout"
            }
        except ConnectionError as e:
            logger.error(f"Connection error: {e}")
            return {
                "url": url,
                "status_code": 0,
                "headers": {},
                "text": f"Connection error: {str(e)}",
                "content": b"",
                "cookies": {},
                "elapsed": 0,
                "is_redirect": False,
                "error": "connection"
            }
        except RequestException as e:
            logger.error(f"Request error: {e}")
            return {
                "url": url,
                "status_code": 0,
                "headers": {},
                "text": f"Request error: {str(e)}",
                "content": b"",
                "cookies": {},
                "elapsed": 0,
                "is_redirect": False,
                "error": "request"
            }
    
    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make a GET request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="GET",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def post(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = False
    ) -> Dict[str, Any]:
        """
        Make a POST request
        
        Args:
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            files: Files to upload
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="POST",
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            files=files,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def put(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = False
    ) -> Dict[str, Any]:
        """
        Make a PUT request
        
        Args:
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            files: Files to upload
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="PUT",
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            files=files,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def delete(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = False
    ) -> Dict[str, Any]:
        """
        Make a DELETE request
        
        Args:
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="DELETE",
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def head(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = False,
        verify: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make a HEAD request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="HEAD",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def options(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = True,
        verify: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make an OPTIONS request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="OPTIONS",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            use_cache=use_cache
        )
    
    def clear_cache(self) -> None:
        """
        Clear the response cache
        """
        self.response_cache = {}
        logger.debug("Response cache cleared")
    
    def rotate_user_agent(self) -> str:
        """
        Rotate the User-Agent header
        
        Returns:
            The new User-Agent string
        """
        new_user_agent = random.choice(self.user_agents)
        self.session.headers.update({"User-Agent": new_user_agent})
        logger.debug(f"Rotated User-Agent to: {new_user_agent}")
        return new_user_agent
