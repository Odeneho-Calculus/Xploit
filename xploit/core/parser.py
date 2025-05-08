"""
xploit/core/parser.py - Response parsing functionality
"""

import re
import logging
from bs4 import BeautifulSoup
import json
from urllib.parse import urlparse, parse_qs, urljoin

logger = logging.getLogger("xploit.core.parser")

class ResponseParser:
    """Parse HTTP responses to extract useful information"""
    
    def __init__(self, response, base_url=None):
        """
        Initialize parser with an HTTP response
        
        Args:
            response: HTTP response object with text/content and headers
            base_url (str, optional): Base URL for resolving relative URLs
        """
        self.response = response
        self.base_url = base_url or ""
        self.soup = None
        self._init_soup()
    
    def _init_soup(self):
        """Initialize BeautifulSoup parser if response is HTML"""
        # Handle both Response objects and dictionary responses from HttpClient
        if isinstance(self.response, dict):
            content_type = self.response.get('headers', {}).get('Content-Type', '').lower()
            response_text = self.response.get('text', '')
        else:
            content_type = getattr(self.response, 'headers', {}).get('Content-Type', '').lower()
            response_text = getattr(self.response, 'text', '')
        
        if 'text/html' in content_type or (not content_type and response_text.strip().startswith('<')):
            try:
                self.soup = BeautifulSoup(response_text, 'lxml')
            except Exception as e:
                logger.warning(f"Error parsing HTML: {str(e)}")
                try:
                    # Fallback to html.parser
                    self.soup = BeautifulSoup(response_text, 'html.parser')
                except Exception as e2:
                    logger.error(f"Failed to parse HTML with fallback parser: {str(e2)}")
    
    def extract_forms(self):
        """Extract forms from the response"""
        if not self.soup:
            return []
        
        forms = []
        for form in self.soup.find_all('form'):
            form_data = {
                'action': urljoin(self.base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Extract inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text') if input_tag.name == 'input' else input_tag.name,
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                
                if input_data['name']:  # Only include inputs with names
                    form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_links(self):
        """Extract links from the response"""
        if not self.soup:
            return []
        
        links = []
        for a_tag in self.soup.find_all('a', href=True):
            href = a_tag.get('href', '')
            if href and not href.startswith('#'):  # Skip anchor links
                links.append({
                    'url': urljoin(self.base_url, href),
                    'text': a_tag.get_text(strip=True),
                    'target': a_tag.get('target', '')
                })
        
        return links
    
    def extract_scripts(self):
        """Extract JavaScript from the response"""
        if not self.soup:
            return []
        
        scripts = []
        for script in self.soup.find_all('script'):
            script_content = script.string or ''
            script_src = script.get('src', '')
            
            if script_src:
                scripts.append({
                    'type': 'external',
                    'src': urljoin(self.base_url, script_src),
                    'content': None
                })
            elif script_content.strip():
                scripts.append({
                    'type': 'inline',
                    'src': None,
                    'content': script_content
                })
        
        return scripts
    
    def extract_comments(self):
        """Extract HTML comments from the response"""
        if not self.soup:
            return []
        
        comments = []
        # Import Comment class from bs4
        from bs4.element import Comment
        
        for comment in self.soup.find_all(string=lambda text: isinstance(text, Comment)):
            comments.append(comment.strip())
        
        return comments
    
    def extract_hidden_inputs(self):
        """Extract hidden inputs from the response"""
        if not self.soup:
            return []
        
        hidden_inputs = []
        for hidden in self.soup.find_all('input', type='hidden'):
            hidden_inputs.append({
                'name': hidden.get('name', ''),
                'value': hidden.get('value', '')
            })
        
        return hidden_inputs
    
    def detect_json(self):
        """Detect if response is JSON and parse it"""
        # Handle both Response objects and dictionary responses from HttpClient
        if isinstance(self.response, dict):
            content_type = self.response.get('headers', {}).get('Content-Type', '').lower()
            response_text = self.response.get('text', '')
        else:
            content_type = getattr(self.response, 'headers', {}).get('Content-Type', '').lower()
            response_text = getattr(self.response, 'text', '')
        
        if 'application/json' in content_type:
            try:
                return json.loads(response_text)
            except json.JSONDecodeError:
                logger.warning("Response claims to be JSON but couldn't be parsed")
                return None
        
        # Try to parse as JSON even if content type doesn't match
        try:
            text = response_text.strip()
            if text.startswith('{') and text.endswith('}') or text.startswith('[') and text.endswith(']'):
                return json.loads(text)
        except json.JSONDecodeError:
            return None
        
        return None
    
    def extract_tokens(self):
        """Extract potential security tokens from the response"""
        tokens = []
        
        # Get response text based on response type
        if isinstance(self.response, dict):
            response_text = self.response.get('text', '')
        else:
            response_text = getattr(self.response, 'text', '')
        
        # Look for common token patterns in the response text
        token_patterns = [
            (r'csrf[_\-]token[\'"\s:=]+([\'"])([^\'"]*)([\'"])', 'CSRF Token'),
            (r'authenticity_token[\'"\s:=]+([\'"])([^\'"]*)([\'"])', 'Authenticity Token'),
            (r'_token[\'"\s:=]+([\'"])([^\'"]*)([\'"])', 'Generic Token'),
            (r'token[\'"\s:=]+([\'"])([a-zA-Z0-9_\-.]+)([\'"])', 'Generic Token')
        ]
        
        for pattern, token_type in token_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if len(match) >= 3:  # Make sure we have the value (should be in group 2)
                    tokens.append({
                        'type': token_type,
                        'value': match[1],
                        'context': response_text[max(0, response_text.find(match[1])-20):
                                                min(len(response_text), response_text.find(match[1])+len(match[1])+20)]
                    })
        
        # Look for hidden inputs that might be tokens
        if self.soup:
            for hidden in self.soup.find_all('input', type='hidden'):
                name = hidden.get('name', '').lower()
                value = hidden.get('value', '')
                
                if name and value and ('token' in name or 'csrf' in name or 'xsrf' in name):
                    tokens.append({
                        'type': 'Hidden Input Token',
                        'name': name,
                        'value': value
                    })
        
        return tokens
    
    def extract_potential_endpoints(self):
        """Extract potential API endpoints from the response"""
        endpoints = set()
        
        # Extract from JavaScript
        if self.soup:
            for script in self.soup.find_all('script'):
                if script.string:
                    # Look for API URL patterns
                    url_patterns = [
                        r'[\'"](/api/[^\'"\s]+)[\'"]',
                        r'[\'"](/v[0-9]+/[^\'"\s]+)[\'"]',
                        r'url:\s*[\'"]([^\'"\s]+)[\'"]',
                        r'endpoint[\'"\s:=]+([\'"])([^\'"]*)([\'"])'
                    ]
                    
                    for pattern in url_patterns:
                        for match in re.findall(pattern, script.string):
                            if isinstance(match, tuple):
                                endpoint = match[1] if len(match) > 1 else match[0]
                            else:
                                endpoint = match
                                
                            if endpoint.startswith('/'):
                                # Relative path
                                endpoints.add(urljoin(self.base_url, endpoint))
                            elif endpoint.startswith('http'):
                                # Absolute URL
                                endpoints.add(endpoint)
        
        return list(endpoints)
    
    def find_patterns(self):
        """Find interesting patterns in the response"""
        patterns = {
            'emails': [],
            'phones': [],
            'credit_cards': [],
            'social_security': [],
            'ips': [],
            'urls': [],
            'suspicious': []
        }
        
        # Get response text based on response type
        if isinstance(self.response, dict):
            response_text = self.response.get('text', '')
        else:
            response_text = getattr(self.response, 'text', '')
        
        # Email pattern
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        patterns['emails'] = list(set(re.findall(email_pattern, response_text)))
        
        # Phone pattern (simplified for demonstration)
        phone_pattern = r'(\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'
        patterns['phones'] = list(set(re.findall(phone_pattern, response_text)))
        
        # Credit card pattern (simplified)
        cc_pattern = r'(?:\d{4}[\s-]?){4}|\d{16}'
        matches = re.findall(cc_pattern, response_text)
        # Basic validation (remove obvious non-credit card numbers)
        patterns['credit_cards'] = [m for m in matches if len(m.replace('-', '').replace(' ', '')) == 16]
        
        # SSN pattern (US)
        ssn_pattern = r'\d{3}-\d{2}-\d{4}'
        patterns['social_security'] = list(set(re.findall(ssn_pattern, response_text)))
        
        # IP address pattern
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        # Basic validation
        ip_matches = re.findall(ip_pattern, response_text)
        valid_ips = []
        for ip in ip_matches:
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                valid_ips.append(ip)
        patterns['ips'] = valid_ips
        
        # URL pattern
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
        patterns['urls'] = list(set(re.findall(url_pattern, response_text)))
        
        # Look for suspicious patterns that might indicate vulnerability
        suspicious_patterns = [
            (r'(error|exception|warning|fatal|undefined|not found).*?(in|at)\s+.*?\.php', 'PHP Error'),
            (r'(error|exception|warning|fatal)\s*:\s*', 'General Error'),
            (r'(SELECT|INSERT|UPDATE|DELETE|UNION|JOIN).*?FROM\s+\w+', 'SQL Query'),
            (r'(ORA|MYSQL|SQLSTATE)\-[0-9]+', 'Database Error'),
            (r'<b>Warning</b>:\s+', 'PHP Warning'),
            (r'<b>Fatal error</b>:\s+', 'PHP Fatal Error'),
            (r'(username|password|user_id|uid)=(.*?)(&|$)', 'Credential Leak'),
            (r'(api_key|apikey|token|secret|password)=([a-zA-Z0-9_\-\.]+)', 'API Key/Secret')
        ]
        
        for pattern, pattern_type in suspicious_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    value = match[0] + (match[1] if len(match) > 1 else '')
                else:
                    value = match
                
                patterns['suspicious'].append({
                    'type': pattern_type,
                    'value': value
                })
        
        return patterns
    
    def extract_error_messages(self):
        """Extract potential error messages from the response"""
        errors = []
        
        # Get response data based on response type
        if isinstance(self.response, dict):
            status_code = self.response.get('status_code', 0)
            response_text = self.response.get('text', '')
        else:
            status_code = getattr(self.response, 'status_code', 0)
            response_text = getattr(self.response, 'text', '')
        
        # Check for common error status codes
        if 400 <= status_code < 600:
            errors.append({
                'type': 'HTTP Error',
                'code': status_code,
                'message': f"HTTP {status_code}"
            })
        
        # Look for common error patterns in HTML
        if self.soup:
            error_containers = self.soup.select('.error, .alert, .danger, #error, [role="alert"]')
            for container in error_containers:
                errors.append({
                    'type': 'Error UI Element',
                    'message': container.get_text(strip=True)[:200]
                })
        
        # Look for common error keywords in the response text
        error_patterns = [
            r'(error|exception|warning|fail)[\s:]+([^\n]{5,100})',
            r'(sql syntax|sql error|ORA-\d+|mysql error)',
            r'(undefined|failed to|unable to|cannot|invalid|timeout|permission denied)'
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    message = match[0] + ': ' + match[1] if len(match) > 1 else match[0]
                else:
                    message = match
                    
                # Get some context around the error
                context_start = max(0, response_text.find(message) - 20)
                context_end = min(len(response_text), response_text.find(message) + len(message) + 20)
                context = response_text[context_start:context_end]
                
                errors.append({
                    'type': 'Error Message',
                    'message': message[:200],
                    'context': context
                })
        
        return errors
    
    def extract_metadata(self):
        """Extract metadata from the response"""
        metadata = {
            'headers': dict(self.response.headers),
            'status_code': self.response.status_code,
            'content_type': self.response.headers.get('Content-Type', 'unknown'),
            'content_length': len(self.response.content),
            'cookies': self.response.cookies.get_dict() if hasattr(self.response, 'cookies') else {}
        }
        
        # Extract meta tags
        if self.soup:
            metadata['meta_tags'] = []
            for meta in self.soup.find_all('meta'):
                meta_data = {}
                for attr in meta.attrs:
                    meta_data[attr] = meta.get(attr)
                metadata['meta_tags'].append(meta_data)
            
            # Extract title
            title_tag = self.soup.find('title')
            metadata['title'] = title_tag.get_text(strip=True) if title_tag else None
        
        return metadata