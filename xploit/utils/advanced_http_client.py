"""
xploit/utils/advanced_http_client.py - Advanced HTTP client with real-time capabilities
"""

import time
import json
import logging
import hashlib
import random
import asyncio
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, Optional, Tuple, Union, List, Any, Callable

import requests
import aiohttp
import httpx
from requests.exceptions import RequestException, Timeout, ConnectionError
from requests.structures import CaseInsensitiveDict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("xploit.utils.advanced_http_client")

class AdvancedHttpClient:
    """Advanced HTTP client with real-time capabilities"""
    
    def __init__(
        self,
        user_agent: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: int = 30,
        delay: float = 0.5,
        max_retries: int = 3,
        verify_ssl: bool = True,
        http2: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        persistent_connections: bool = True,
        connection_timeout: int = 10,
        read_timeout: int = 30,
        enable_http2: bool = False,
        enable_compression: bool = True
    ):
        """
        Initialize the advanced HTTP client
        
        Args:
            user_agent: Custom User-Agent string
            headers: Custom HTTP headers
            cookies: Cookies to include with requests
            proxy: Proxy URL
            auth: Authentication tuple (username, password)
            timeout: Request timeout in seconds
            delay: Delay between requests in seconds
            max_retries: Maximum number of retries for failed requests
            verify_ssl: Whether to verify SSL certificates
            http2: Whether to use HTTP/2
            follow_redirects: Whether to follow redirects
            max_redirects: Maximum number of redirects to follow
            persistent_connections: Whether to use persistent connections
            connection_timeout: Connection timeout in seconds
            read_timeout: Read timeout in seconds
            enable_http2: Whether to enable HTTP/2
            enable_compression: Whether to enable compression
        """
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.enable_http2 = enable_http2
        self.enable_compression = enable_compression
        
        self.last_request_time = 0
        self.request_count = 0
        self.response_cache = {}
        self.streaming_connections = {}
        self.event_callbacks = {}
        
        # User agent rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0"
        ]
        default_user_agent = user_agent or random.choice(self.user_agents)
        
        # Set up the requests session
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504, 403, 408],
            allowed_methods=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"],
            respect_retry_after_header=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=50)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "User-Agent": default_user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br" if enable_compression else "identity",
            "Connection": "keep-alive" if persistent_connections else "close",
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
        
        # Set up the httpx client for HTTP/2 support
        if http2:
            try:
                self.http2_client = httpx.Client(
                    http2=True,
                    verify=verify_ssl,
                    timeout=httpx.Timeout(connect=connection_timeout, read=read_timeout),
                    follow_redirects=follow_redirects,
                    proxies=proxy,
                    headers={
                        "User-Agent": default_user_agent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept-Encoding": "gzip, deflate, br" if enable_compression else "identity"
                    }
                )
                if headers:
                    for key, value in headers.items():
                        self.http2_client.headers[key] = value
                if cookies:
                    for key, value in cookies.items():
                        self.http2_client.cookies.set(key, value)
                
                self.http2_available = True
                logger.debug("HTTP/2 client initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize HTTP/2 client: {str(e)}")
                self.http2_available = False
        else:
            self.http2_available = False
        
        # Set up the async event loop
        self.loop = asyncio.new_event_loop()
        self.async_thread = None
        self.async_running = False
    
    def _start_async_loop(self) -> None:
        """Start the async event loop in a separate thread"""
        if self.async_thread is not None and self.async_thread.is_alive():
            return
        
        def _run_async_loop():
            asyncio.set_event_loop(self.loop)
            self.async_running = True
            self.loop.run_forever()
        
        self.async_thread = threading.Thread(target=_run_async_loop, daemon=True)
        self.async_thread.start()
        logger.debug("Started async event loop")
    
    def _stop_async_loop(self) -> None:
        """Stop the async event loop"""
        if self.async_running and not self.loop.is_closed():
            self.async_running = False
            self.loop.call_soon_threadsafe(self.loop.stop)
            if self.async_thread is not None:
                self.async_thread.join(timeout=2.0)
            self.loop.close()
            logger.debug("Stopped async event loop")
    
    def _throttle_request(self) -> None:
        """Throttle requests to avoid overloading the server"""
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
            "is_redirect": response.is_redirect,
            "history": [{"url": r.url, "status_code": r.status_code} for r in response.history],
            "encoding": response.encoding,
            "reason": response.reason,
            "ok": response.ok
        }
    
    def _process_httpx_response(self, response: httpx.Response) -> Dict[str, Any]:
        """
        Process the httpx response and return a standardized format
        
        Args:
            response: The httpx.Response object
            
        Returns:
            Dict containing processed response data
        """
        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "text": response.text,
            "content": response.content,
            "cookies": dict(response.cookies),
            "elapsed": response.elapsed.total_seconds(),
            "is_redirect": response.is_redirect,
            "history": [{"url": str(r.url), "status_code": r.status_code} for r in response.history],
            "encoding": response.encoding,
            "reason": response.reason_phrase,
            "ok": response.is_success,
            "http_version": response.http_version
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
        allow_redirects: Optional[bool] = None,
        verify: Optional[bool] = None,
        use_cache: bool = True,
        use_http2: Optional[bool] = None,
        stream: bool = False,
        cert: Optional[Union[str, Tuple[str, str]]] = None
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
            use_http2: Whether to use HTTP/2 (if available)
            stream: Whether to stream the response
            cert: SSL client certificate
            
        Returns:
            Dict containing response data
        """
        method = method.upper()
        timeout = timeout or self.timeout
        allow_redirects = self.follow_redirects if allow_redirects is None else allow_redirects
        verify = self.verify_ssl if verify is None else verify
        use_http2 = self.http2_available if use_http2 is None else (use_http2 and self.http2_available)
        
        # Check cache if enabled
        if use_cache and not stream:
            cache_key = self._get_cache_key(method, url, params=params, data=data, json=json, headers=headers)
            if cache_key in self.response_cache:
                logger.debug(f"Cache hit for {method} {url}")
                return self.response_cache[cache_key]
        
        # Throttle request if needed
        self._throttle_request()
        
        # Log the request
        logger.debug(f"Making {method} request to {url}")
        
        try:
            # Use HTTP/2 client if requested and available
            if use_http2:
                # Make the request with httpx
                response = self.http2_client.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json,
                    headers=headers,
                    cookies=cookies,
                    auth=auth,
                    timeout=timeout,
                    follow_redirects=allow_redirects,
                    verify=verify,
                    cert=cert
                )
                
                # Process the response
                processed_response = self._process_httpx_response(response)
                
                # Add HTTP/2 specific information
                processed_response["http2"] = True
                
            else:
                # Make the request with requests
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
                    verify=verify,
                    cert=cert,
                    stream=stream
                )
                
                if stream:
                    # Return a streaming response
                    return {
                        "url": response.url,
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "cookies": dict(response.cookies),
                        "is_redirect": response.is_redirect,
                        "encoding": response.encoding,
                        "reason": response.reason,
                        "ok": response.ok,
                        "stream": response,
                        "iter_content": response.iter_content,
                        "iter_lines": response.iter_lines
                    }
                
                # Process the response
                processed_response = self._process_response(response)
                processed_response["http2"] = False
            
            # Cache the response if enabled
            if use_cache and not stream:
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
                "error": "timeout",
                "http2": use_http2
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
                "error": "connection",
                "http2": use_http2
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
                "error": "request",
                "http2": use_http2
            }
    
    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: Optional[bool] = None,
        verify: Optional[bool] = None,
        use_cache: bool = True,
        use_http2: Optional[bool] = None,
        stream: bool = False
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
            use_http2: Whether to use HTTP/2 (if available)
            stream: Whether to stream the response
            
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
            use_cache=use_cache,
            use_http2=use_http2,
            stream=stream
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
        allow_redirects: Optional[bool] = None,
        verify: Optional[bool] = None,
        use_cache: bool = False,
        use_http2: Optional[bool] = None
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
            use_http2: Whether to use HTTP/2 (if available)
            
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
            use_cache=use_cache,
            use_http2=use_http2
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
        allow_redirects: Optional[bool] = None,
        verify: Optional[bool] = None,
        use_cache: bool = False,
        use_http2: Optional[bool] = None
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
            use_http2: Whether to use HTTP/2 (if available)
            
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
            use_cache=use_cache,
            use_http2=use_http2
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
        allow_redirects: Optional[bool] = None,
        verify: Optional[bool] = None,
        use_cache: bool = False,
        use_http2: Optional[bool] = None
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
            use_http2: Whether to use HTTP/2 (if available)
            
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
            use_cache=use_cache,
            use_http2=use_http2
        )
    
    def head(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: bool = False,  # Default for HEAD is False
        verify: Optional[bool] = None,
        use_cache: bool = True,
        use_http2: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Make a HEAD request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            allow_redirects: Whether to follow redirects (default: False)
            verify: Whether to verify SSL certificates
            use_cache: Whether to use the response cache
            use_http2: Whether to use HTTP/2 (if available)
            
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
            use_cache=use_cache,
            use_http2=use_http2
        )
    
    def options(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        allow_redirects: Optional[bool] = None,
        verify: Optional[bool] = None,
        use_cache: bool = True,
        use_http2: Optional[bool] = None
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
            use_http2: Whether to use HTTP/2 (if available)
            
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
            use_cache=use_cache,
            use_http2=use_http2
        )
    
    def patch(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        allow_redirects: Optional[bool] = None,
        verify: Optional[bool] = None,
        use_cache: bool = False,
        use_http2: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Make a PATCH request
        
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
            use_http2: Whether to use HTTP/2 (if available)
            
        Returns:
            Dict containing response data
        """
        return self.request(
            method="PATCH",
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
            use_cache=use_cache,
            use_http2=use_http2
        )
    
    def stream_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
        verify: Optional[bool] = None,
        chunk_size: int = 1024,
        callback: Optional[Callable[[bytes], None]] = None
    ) -> Dict[str, Any]:
        """
        Make a streaming request and process chunks with a callback
        
        Args:
            method: HTTP method
            url: URL to request
            params: Query parameters
            data: Form data
            json: JSON data
            headers: HTTP headers
            cookies: Cookies
            auth: Authentication credentials
            timeout: Request timeout
            verify: Whether to verify SSL certificates
            chunk_size: Size of chunks to read
            callback: Callback function to process chunks
            
        Returns:
            Dict containing response metadata
        """
        # Make the streaming request
        response_data = self.request(
            method=method,
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            auth=auth,
            timeout=timeout,
            verify=verify,
            stream=True
        )
        
        if "error" in response_data:
            return response_data
        
        # Get the streaming response
        response = response_data.get("stream")
        
        # Process the stream
        total_size = 0
        chunks = []
        
        try:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    total_size += len(chunk)
                    
                    # Call the callback if provided
                    if callback:
                        callback(chunk)
                    else:
                        chunks.append(chunk)
            
            # Close the response
            response.close()
            
            # Update the response data
            response_data["total_size"] = total_size
            
            if not callback:
                # Combine the chunks if no callback was provided
                content = b"".join(chunks)
                response_data["content"] = content
                try:
                    response_data["text"] = content.decode(response.encoding or "utf-8")
                except UnicodeDecodeError:
                    response_data["text"] = None
            
            return response_data
            
        except Exception as e:
            logger.error(f"Error streaming request: {str(e)}")
            response.close()
            return {
                **response_data,
                "error": f"Streaming error: {str(e)}",
                "total_size": total_size
            }
    
    def stream_get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        verify: Optional[bool] = None,
        chunk_size: int = 1024,
        callback: Optional[Callable[[bytes], None]] = None
    ) -> Dict[str, Any]:
        """
        Make a streaming GET request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            timeout: Request timeout
            verify: Whether to verify SSL certificates
            chunk_size: Size of chunks to read
            callback: Callback function to process chunks
            
        Returns:
            Dict containing response metadata
        """
        return self.stream_request(
            method="GET",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            verify=verify,
            chunk_size=chunk_size,
            callback=callback
        )
    
    def connect_sse(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        event_callback: Callable[[Dict[str, Any]], None] = None,
        reconnect: bool = True,
        max_retries: int = 5,
        retry_delay: int = 3
    ) -> str:
        """
        Connect to a Server-Sent Events (SSE) endpoint
        
        Args:
            url: URL of the SSE endpoint
            params: Query parameters
            headers: HTTP headers
            cookies: Cookies
            auth: Authentication credentials
            event_callback: Callback function for SSE events
            reconnect: Whether to automatically reconnect on disconnection
            max_retries: Maximum number of reconnection attempts
            retry_delay: Delay between reconnection attempts in seconds
            
        Returns:
            str: Connection ID
        """
        # Start the async loop if not already running
        if not self.async_running:
            self._start_async_loop()
        
        # Generate a connection ID
        connection_id = hashlib.md5(f"{url}:{time.time()}".encode()).hexdigest()
        
        # Set up SSE-specific headers
        sse_headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }
        
        if headers:
            sse_headers.update(headers)
        
        # Store the event callback
        self.event_callbacks[connection_id] = event_callback
        
        # Define the SSE client coroutine
        async def _sse_client():
            retry_count = 0
            
            while True:
                try:
                    # Create a ClientSession
                    async with aiohttp.ClientSession() as session:
                        # Make the request
                        async with session.get(
                            url,
                            params=params,
                            headers=sse_headers,
                            cookies=cookies,
                            auth=aiohttp.BasicAuth(*auth) if auth else None,
                            timeout=aiohttp.ClientTimeout(total=None)  # No timeout for SSE
                        ) as response:
                            # Check if the response is successful
                            if response.status != 200:
                                logger.error(f"SSE connection failed with status {response.status}: {await response.text()}")
                                break
                            
                            # Process the SSE stream
                            buffer = ""
                            event_type = None
                            event_id = None
                            event_data = []
                            
                            # Read the response line by line
                            async for line in response.content:
                                line = line.decode("utf-8").rstrip()
                                
                                # Empty line means the end of an event
                                if not line:
                                    if event_data:
                                        # Process the event
                                        event = {
                                            "type": event_type or "message",
                                            "data": "\n".join(event_data),
                                            "id": event_id,
                                            "timestamp": time.time()
                                        }
                                        
                                        # Call the callback
                                        if event_callback:
                                            try:
                                                # Try to parse JSON data
                                                try:
                                                    event["json"] = json.loads(event["data"])
                                                except:
                                                    pass
                                                
                                                # Call the callback
                                                event_callback(event)
                                            except Exception as e:
                                                logger.error(f"Error in SSE event callback: {str(e)}")
                                        
                                        # Reset event data
                                        event_type = None
                                        event_id = None
                                        event_data = []
                                    continue
                                
                                # Parse the line
                                if line.startswith("event:"):
                                    event_type = line[6:].strip()
                                elif line.startswith("id:"):
                                    event_id = line[3:].strip()
                                elif line.startswith("data:"):
                                    event_data.append(line[5:].strip())
                                elif line.startswith("retry:"):
                                    # Server-specified retry time
                                    try:
                                        retry_delay = int(line[6:].strip()) / 1000  # Convert ms to seconds
                                    except ValueError:
                                        pass
                                
                            # If we get here, the connection was closed
                            logger.warning(f"SSE connection closed: {url}")
                            
                            # Reset retry count on successful connection
                            retry_count = 0
                
                except Exception as e:
                    logger.error(f"SSE connection error: {str(e)}")
                
                # Check if we should reconnect
                if not reconnect or connection_id not in self.streaming_connections:
                    break
                
                # Increment retry count
                retry_count += 1
                
                # Check if we've reached the maximum number of retries
                if max_retries > 0 and retry_count > max_retries:
                    logger.error(f"SSE connection failed after {max_retries} retries")
                    break
                
                # Wait before reconnecting
                logger.info(f"Reconnecting to SSE endpoint in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
        
        # Store the connection
        self.streaming_connections[connection_id] = {
            "type": "sse",
            "url": url,
            "task": asyncio.run_coroutine_threadsafe(_sse_client(), self.loop)
        }
        
        logger.info(f"Started SSE connection to {url}")
        return connection_id
    
    def connect_websocket(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Dict[str, str]] = None,
        message_callback: Callable[[Dict[str, Any]], None] = None,
        reconnect: bool = True,
        max_retries: int = 5,
        retry_delay: int = 3
    ) -> str:
        """
        Connect to a WebSocket endpoint
        
        Args:
            url: URL of the WebSocket endpoint
            headers: HTTP headers
            cookies: Cookies
            auth: Authentication data to send after connection
            message_callback: Callback function for WebSocket messages
            reconnect: Whether to automatically reconnect on disconnection
            max_retries: Maximum number of reconnection attempts
            retry_delay: Delay between reconnection attempts in seconds
            
        Returns:
            str: Connection ID
        """
        # Start the async loop if not already running
        if not self.async_running:
            self._start_async_loop()
        
        # Generate a connection ID
        connection_id = hashlib.md5(f"{url}:{time.time()}".encode()).hexdigest()
        
        # Store the message callback
        self.event_callbacks[connection_id] = message_callback
        
        # Define the WebSocket client coroutine
        async def _websocket_client():
            retry_count = 0
            
            while True:
                try:
                    # Connect to the WebSocket
                    async with websockets.connect(url, extra_headers=headers) as websocket:
                        logger.info(f"Connected to WebSocket: {url}")
                        
                        # Send authentication if required
                        if auth:
                            await websocket.send(json.dumps(auth))
                        
                        # Listen for messages
                        while True:
                            try:
                                message = await websocket.recv()
                                
                                # Process the message
                                if message_callback:
                                    try:
                                        # Try to parse JSON data
                                        try:
                                            data = json.loads(message)
                                            message_type = "json"
                                        except:
                                            data = message
                                            message_type = "text"
                                        
                                        # Call the callback
                                        message_callback({
                                            "type": message_type,
                                            "data": data,
                                            "timestamp": time.time()
                                        })
                                    except Exception as e:
                                        logger.error(f"Error in WebSocket message callback: {str(e)}")
                            
                            except websockets.exceptions.ConnectionClosed:
                                logger.warning(f"WebSocket connection closed: {url}")
                                break
                        
                        # Reset retry count on successful connection
                        retry_count = 0
                
                except Exception as e:
                    logger.error(f"WebSocket connection error: {str(e)}")
                
                # Check if we should reconnect
                if not reconnect or connection_id not in self.streaming_connections:
                    break
                
                # Increment retry count
                retry_count += 1
                
                # Check if we've reached the maximum number of retries
                if max_retries > 0 and retry_count > max_retries:
                    logger.error(f"WebSocket connection failed after {max_retries} retries")
                    break
                
                # Wait before reconnecting
                logger.info(f"Reconnecting to WebSocket in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
        
        # Store the connection
        self.streaming_connections[connection_id] = {
            "type": "websocket",
            "url": url,
            "task": asyncio.run_coroutine_threadsafe(_websocket_client(), self.loop)
        }
        
        logger.info(f"Started WebSocket connection to {url}")
        return connection_id
    
    def send_websocket_message(self, connection_id: str, message: Union[str, Dict[str, Any]]) -> bool:
        """
        Send a message to a WebSocket connection
        
        Args:
            connection_id: Connection ID
            message: Message to send (string or JSON-serializable object)
            
        Returns:
            bool: True if the message was sent successfully, False otherwise
        """
        if connection_id not in self.streaming_connections:
            logger.error(f"WebSocket connection not found: {connection_id}")
            return False
        
        if self.streaming_connections[connection_id]["type"] != "websocket":
            logger.error(f"Connection {connection_id} is not a WebSocket connection")
            return False
        
        # Convert the message to a string if it's a dict
        if isinstance(message, dict):
            message = json.dumps(message)
        
        # Send the message
        try:
            websocket = self.streaming_connections[connection_id].get("websocket")
            if websocket:
                asyncio.run_coroutine_threadsafe(websocket.send(message), self.loop)
                return True
            else:
                logger.error(f"WebSocket connection {connection_id} is not active")
                return False
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {str(e)}")
            return False
    
    def close_connection(self, connection_id: str) -> bool:
        """
        Close a streaming connection
        
        Args:
            connection_id: Connection ID
            
        Returns:
            bool: True if the connection was closed successfully, False otherwise
        """
        if connection_id not in self.streaming_connections:
            logger.error(f"Connection not found: {connection_id}")
            return False
        
        # Cancel the task
        try:
            self.streaming_connections[connection_id]["task"].cancel()
        except Exception as e:
            logger.error(f"Error canceling connection task: {str(e)}")
        
        # Remove the connection
        del self.streaming_connections[connection_id]
        
        # Remove the callback
        if connection_id in self.event_callbacks:
            del self.event_callbacks[connection_id]
        
        logger.info(f"Closed connection: {connection_id}")
        return True
    
    def close_all_connections(self) -> None:
        """Close all streaming connections"""
        for connection_id in list(self.streaming_connections.keys()):
            self.close_connection(connection_id)
    
    def clear_cache(self) -> None:
        """Clear the response cache"""
        self.response_cache.clear()
        logger.debug("Cleared response cache")
    
    def close(self) -> None:
        """Close the HTTP client and release resources"""
        # Close all streaming connections
        self.close_all_connections()
        
        # Stop the async loop
        self._stop_async_loop()
        
        # Close the HTTP/2 client if available
        if self.http2_available:
            try:
                self.http2_client.close()
            except:
                pass
        
        # Close the requests session
        try:
            self.session.close()
        except:
            pass
        
        logger.debug("Closed HTTP client")