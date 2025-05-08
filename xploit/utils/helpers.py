"""
xploit/utils/helpers.py - Helper functions for the XPLOIT tool
"""

import re
import os
import logging
import hashlib
import random
import string
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def setup_logging(level=logging.INFO, no_color=False):
    """
    Set up logging configuration with optional colored output
    
    Args:
        level: The logging level (default: INFO)
        no_color: Whether to disable colored output (default: False)
    """
    # Basic logging format without colors
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add console handler
    console_handler = logging.StreamHandler()
    
    if no_color:
        formatter = logging.Formatter(
            log_format,
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        # Try to use colorlog if available
        try:
            from colorlog import ColoredFormatter
            formatter = ColoredFormatter(
                "%(log_color)s" + log_format + "%(reset)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                reset=True,
                log_colors={
                    'DEBUG': 'cyan',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'red,bg_white',
                }
            )
        except ImportError:
            # Fallback to standard logging if colorlog is not available
            formatter = logging.Formatter(
                log_format,
                datefmt="%Y-%m-%d %H:%M:%S"
            )
    
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

def validate_url(url):
    """
    Validate that a URL is properly formatted
    
    Args:
        url: The URL to validate
        
    Returns:
        bool: True if the URL is valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def get_param_value_from_url(url, param):
    """
    Extract the value of a parameter from a URL
    
    Args:
        url: The URL to parse
        param: The parameter name to extract
        
    Returns:
        str: The parameter value, or None if not found
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if param in query_params:
        # Return the first value if there are multiple
        return query_params[param][0]
    
    return None

def replace_param_in_url(url, param, value):
    """
    Replace or add a parameter value in a URL
    
    Args:
        url: The URL to modify
        param: The parameter name
        value: The new parameter value
        
    Returns:
        str: The modified URL
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    # Update the parameter value
    query_params[param] = [value]
    
    # Rebuild the query string
    new_query = urlencode(query_params, doseq=True)
    
    # Rebuild the URL
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

def generate_random_string(length=10):
    """
    Generate a random string of specified length
    
    Args:
        length: The length of the string to generate (default: 10)
        
    Returns:
        str: A random string
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def hash_response(response_text):
    """
    Generate a hash for a response text to identify unique responses
    
    Args:
        response_text: The response text to hash
        
    Returns:
        str: The MD5 hash of the response text
    """
    return hashlib.md5(response_text.encode('utf-8')).hexdigest()

def normalize_html(html_content):
    """
    Normalize HTML content by removing whitespace and comments
    
    Args:
        html_content: The HTML content to normalize
        
    Returns:
        str: The normalized HTML content
    """
    if not html_content:
        return ""
        
    # Remove HTML comments
    html_content = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)
    
    # Remove extra whitespace
    html_content = re.sub(r'\s+', ' ', html_content)
    
    # Remove whitespace between tags
    html_content = re.sub(r'>\s+<', '><', html_content)
    
    return html_content.strip()

def extract_page_title(html_content):
    """
    Extract the title from HTML content
    
    Args:
        html_content: The HTML content to parse
        
    Returns:
        str: The page title, or None if not found
    """
    if not html_content:
        return None
        
    match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    
    return None

def extract_forms(html_content):
    """
    Extract forms from HTML content
    
    Args:
        html_content: The HTML content to parse
        
    Returns:
        list: A list of dictionaries containing form information
    """
    if not html_content:
        return []
        
    forms = []
    form_matches = re.finditer(r'<form[^>]*>(.*?)</form>', html_content, re.IGNORECASE | re.DOTALL)
    
    for form_match in form_matches:
        form_html = form_match.group(0)
        
        # Extract form attributes
        action_match = re.search(r'action=[\'"]([^\'"]*)[\'"]', form_html)
        method_match = re.search(r'method=[\'"]([^\'"]*)[\'"]', form_html)
        
        action = action_match.group(1) if action_match else ""
        method = method_match.group(1) if method_match else "get"
        
        # Extract form inputs
        inputs = []
        input_matches = re.finditer(r'<input[^>]*>', form_html)
        
        for input_match in input_matches:
            input_html = input_match.group(0)
            
            name_match = re.search(r'name=[\'"]([^\'"]*)[\'"]', input_html)
            type_match = re.search(r'type=[\'"]([^\'"]*)[\'"]', input_html)
            value_match = re.search(r'value=[\'"]([^\'"]*)[\'"]', input_html)
            
            name = name_match.group(1) if name_match else ""
            input_type = type_match.group(1) if type_match else "text"
            value = value_match.group(1) if value_match else ""
            
            if name:  # Only include inputs with a name
                inputs.append({
                    "name": name,
                    "type": input_type,
                    "value": value
                })
        
        # Add form information to the list
        forms.append({
            "action": action,
            "method": method.lower(),
            "inputs": inputs
        })
    
    return forms

def extract_links(html_content, base_url=None):
    """
    Extract links from HTML content
    
    Args:
        html_content: The HTML content to parse
        base_url: The base URL to resolve relative URLs (default: None)
        
    Returns:
        list: A list of links found in the HTML content
    """
    if not html_content:
        return []
        
    links = []
    link_matches = re.finditer(r'<a[^>]*href=[\'"]([^\'"]*)[\'"][^>]*>(.*?)</a>', html_content, re.IGNORECASE | re.DOTALL)
    
    for link_match in link_matches:
        href = link_match.group(1)
        text = link_match.group(2).strip()
        
        # Remove HTML tags from the link text
        text = re.sub(r'<[^>]*>', '', text)
        
        # Resolve relative URLs if base_url is provided
        if base_url and href and not href.startswith(('http://', 'https://', 'mailto:', 'tel:', '#')):
            if href.startswith('/'):
                # Absolute path relative to the domain
                parsed_base = urlparse(base_url)
                href = f"{parsed_base.scheme}://{parsed_base.netloc}{href}"
            else:
                # Relative path
                if base_url.endswith('/'):
                    href = f"{base_url}{href}"
                else:
                    base_dir = base_url.rsplit('/', 1)[0]
                    href = f"{base_dir}/{href}"
        
        links.append({
            "href": href,
            "text": text
        })
    
    return links

def extract_emails(text):
    """
    Extract email addresses from text
    
    Args:
        text: The text to parse
        
    Returns:
        list: A list of email addresses found in the text
    """
    if not text:
        return []
        
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    
    return list(set(emails))  # Remove duplicates

def clean_string(text):
    """
    Clean a string by removing extra whitespace and normalizing it
    
    Args:
        text: The string to clean
        
    Returns:
        str: The cleaned string
    """
    if not text:
        return ""
        
    # Replace tabs and newlines with spaces
    text = re.sub(r'[\t\n\r]+', ' ', text)
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()

def is_numeric(value):
    """
    Check if a value is numeric
    
    Args:
        value: The value to check
        
    Returns:
        bool: True if the value is numeric, False otherwise
    """
    try:
        float(value)
        return True
    except (ValueError, TypeError):
        return False

def format_time_duration(seconds):
    """
    Format a time duration in seconds to a human-readable string
    
    Args:
        seconds: The number of seconds
        
    Returns:
        str: A formatted string representing the duration
    """
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes, seconds = divmod(seconds, 60)
        return f"{int(minutes)} minutes, {seconds:.2f} seconds"
    else:
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours)} hours, {int(minutes)} minutes, {seconds:.2f} seconds"

def ensure_directory_exists(directory):
    """
    Ensure that a directory exists, creating it if necessary
    
    Args:
        directory: The directory path
    """
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_unique_filename(base_path, prefix="", suffix=""):
    """
    Generate a unique filename with timestamp
    
    Args:
        base_path: The base directory path
        prefix: A prefix for the filename (default: "")
        suffix: A suffix for the filename (default: "")
        
    Returns:
        str: A unique filename
    """
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    random_str = generate_random_string(5)
    
    filename = f"{prefix}{timestamp}_{random_str}{suffix}"
    return os.path.join(base_path, filename)

def parse_headers_string(headers_string):
    """
    Parse a semicolon-separated string of headers into a dictionary
    
    Args:
        headers_string: A string in the format "header1:value1;header2:value2"
        
    Returns:
        dict: A dictionary of header names and values
    """
    if not headers_string:
        return {}
        
    headers = {}
    header_pairs = headers_string.split(';')
    
    for header_pair in header_pairs:
        if ':' in header_pair:
            name, value = header_pair.split(':', 1)
            headers[name.strip()] = value.strip()
    
    return headers

def parse_cookies_string(cookies_string):
    """
    Parse a semicolon-separated string of cookies into a dictionary
    
    Args:
        cookies_string: A string in the format "name1=value1; name2=value2"
        
    Returns:
        dict: A dictionary of cookie names and values
    """
    if not cookies_string:
        return {}
        
    cookies = {}
    cookie_pairs = cookies_string.split(';')
    
    for cookie_pair in cookie_pairs:
        if '=' in cookie_pair:
            name, value = cookie_pair.split('=', 1)
            cookies[name.strip()] = value.strip()
    
    return cookies

def response_similarity(response1, response2):
    """
    Calculate the similarity between two response texts
    
    Args:
        response1: The first response text
        response2: The second response text
        
    Returns:
        float: A similarity score between 0 and 1
    """
    # Normalize the responses
    r1 = normalize_html(response1)
    r2 = normalize_html(response2)
    
    # If either response is empty, they are not similar
    if not r1 or not r2:
        return 0.0
    
    # Get the lengths
    len1 = len(r1)
    len2 = len(r2)
    
    # If the lengths are very different, they are likely not similar
    if min(len1, len2) / max(len1, len2) < 0.5:
        return 0.0
    
    # Count the number of matching characters
    matching_chars = sum(c1 == c2 for c1, c2 in zip(r1, r2))
    
    # Calculate the similarity as the ratio of matching characters to the longer string
    return matching_chars / max(len1, len2)

def save_data_to_json(data, output_file):
    """
    Save data to a JSON file
    
    Args:
        data: The data to save
        output_file: The output file path
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def load_data_from_json(input_file):
    """
    Load data from a JSON file
    
    Args:
        input_file: The input file path
        
    Returns:
        The loaded data
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def detect_pagination_pattern(urls):
    """
    Detect pagination patterns in a list of URLs
    
    Args:
        urls: A list of URLs to analyze
        
    Returns:
        dict: Information about the detected pagination pattern
    """
    if not urls or len(urls) < 2:
        return None
    
    # Look for common pagination parameters
    pagination_params = ['page', 'p', 'pg', 'pgnum', 'pagenum', 'offset', 'start', 'limit']
    results = {}
    
    for url in urls:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for param in pagination_params:
            if param in query_params:
                value = query_params[param][0]
                if is_numeric(value):
                    if param not in results:
                        results[param] = []
                    results[param].append(int(float(value)))
    
    # If we found pagination parameters, determine the pattern
    for param, values in results.items():
        if len(values) >= 2:
            # Sort the values
            values.sort()
            
            # Check if they form an arithmetic sequence
            diffs = [values[i+1] - values[i] for i in range(len(values)-1)]
            
            if len(set(diffs)) == 1:  # All differences are the same
                return {
                    "parameter": param,
                    "values": values,
                    "step": diffs[0],
                    "is_sequential": True
                }
    
    return None

def extract_social_media(text):
    """
    Extract social media handles and URLs from text
    
    Args:
        text: The text to parse
        
    Returns:
        dict: A dictionary of social media platforms and their handles/URLs
    """
    if not text:
        return {}
        
    social_media = {
        "twitter": [],
        "facebook": [],
        "instagram": [],
        "linkedin": [],
        "github": [],
        "youtube": []
    }
    
    # Twitter handles
    twitter_pattern = r'(?:@([a-zA-Z0-9_]{1,15}))|(?:twitter\.com/([a-zA-Z0-9_]{1,15}))'
    twitter_matches = re.finditer(twitter_pattern, text)
    for match in twitter_matches:
        handle = match.group(1) or match.group(2)
        if handle and handle not in social_media["twitter"]:
            social_media["twitter"].append(handle)
    
    # Facebook URLs
    facebook_pattern = r'(?:facebook\.com/([a-zA-Z0-9.]{5,50}))'
    facebook_matches = re.finditer(facebook_pattern, text)
    for match in facebook_matches:
        handle = match.group(1)
        if handle and handle not in social_media["facebook"]:
            social_media["facebook"].append(handle)
    
    # Instagram handles
    instagram_pattern = r'(?:@([a-zA-Z0-9_.]{1,30}))|(?:instagram\.com/([a-zA-Z0-9_.]{1,30}))'
    instagram_matches = re.finditer(instagram_pattern, text)
    for match in instagram_matches:
        handle = match.group(1) or match.group(2)
        if handle and handle not in social_media["instagram"]:
            social_media["instagram"].append(handle)
    
    # LinkedIn URLs
    linkedin_pattern = r'(?:linkedin\.com/in/([a-zA-Z0-9_-]{5,30}))'
    linkedin_matches = re.finditer(linkedin_pattern, text)
    for match in linkedin_matches:
        handle = match.group(1)
        if handle and handle not in social_media["linkedin"]:
            social_media["linkedin"].append(handle)
    
    # GitHub handles
    github_pattern = r'(?:github\.com/([a-zA-Z0-9_-]{1,39}))'
    github_matches = re.finditer(github_pattern, text)
    for match in github_matches:
        handle = match.group(1)
        if handle and handle not in social_media["github"]:
            social_media["github"].append(handle)
    
    # YouTube channels
    youtube_pattern = r'(?:youtube\.com/(?:channel|user)/([a-zA-Z0-9_-]{1,50}))'
    youtube_matches = re.finditer(youtube_pattern, text)
    for match in youtube_matches:
        handle = match.group(1)
        if handle and handle not in social_media["youtube"]:
            social_media["youtube"].append(handle)
    
    # Remove empty platforms
    return {k: v for k, v in social_media.items() if v}

def extract_phone_numbers(text):
    """
    Extract phone numbers from text
    
    Args:
        text: The text to parse
        
    Returns:
        list: A list of phone numbers found in the text
    """
    if not text:
        return []
        
    # Common phone number patterns with word boundaries to avoid matching random numbers
    patterns = [
        r'\b\+\d{1,3}[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b',  # International format
        r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',  # US format (xxx) xxx-xxxx
        r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # US format xxx-xxx-xxxx
        r'\b\d{5}[-.\s]?\d{6}\b',  # Some European formats
        r'\d{4}[-.\s]?\d{3}[-.\s]?\d{3}'  # Some Asian formats
    ]
    
    phone_numbers = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        phone_numbers.extend(matches)
    
    # Clean and normalize the phone numbers
    cleaned_numbers = []
    for number in phone_numbers:
        # Remove non-digit characters except for the leading +
        cleaned = re.sub(r'[^\d+]', '', number)
        if cleaned and cleaned not in cleaned_numbers:
            cleaned_numbers.append(cleaned)
    
    return cleaned_numbers

def extract_credit_cards(text):
    """
    Extract potential credit card numbers from text
    
    Args:
        text: The text to parse
        
    Returns:
        list: A list of potential credit card numbers found in the text
    """
    if not text:
        return []
        
    # Credit card pattern (simplified)
    # This will match common credit card formats but may have false positives
    pattern = r'(?:\d{4}[-\s]?){3}\d{4}'
    
    matches = re.findall(pattern, text)
    
    # Clean and normalize the credit card numbers
    cleaned_cards = []
    for card in matches:
        # Remove non-digit characters
        cleaned = re.sub(r'[^\d]', '', card)
        
        # Basic validation (length and Luhn algorithm check)
        if len(cleaned) >= 13 and len(cleaned) <= 19 and _is_valid_luhn(cleaned):
            # Mask all but the last 4 digits
            masked = '*' * (len(cleaned) - 4) + cleaned[-4:]
            if masked not in cleaned_cards:
                cleaned_cards.append(masked)
    
    return cleaned_cards

def _is_valid_luhn(card_number):
    """
    Check if a credit card number passes the Luhn algorithm
    
    Args:
        card_number: The card number to check
        
    Returns:
        bool: True if the card number passes the Luhn check, False otherwise
    """
    digits = [int(d) for d in card_number]
    checksum = 0
    
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:  # Odd position (0-indexed from the right)
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    
    return checksum % 10 == 0

def _is_common_js_variable(key):
    """
    Check if a string is likely a common JavaScript variable or library name
    
    Args:
        key: The string to check
        
    Returns:
        bool: True if it's likely a common JS variable, False otherwise
    """
    common_js_terms = [
        'function', 'undefined', 'document', 'window', 'location', 
        'sessiontimeout', 'notification', 'dragdrop', 'formchange', 
        'position', 'dialog', 'warning', 'alert', 'confirm', 'exception',
        'module', 'require', 'exports', 'default', 'component', 'plugin',
        'jquery', 'angular', 'react', 'vue', 'bootstrap', 'foundation',
        'moodle', 'wordpress', 'joomla', 'drupal', 'magento', 'shopify'
    ]
    
    # Check if the key contains or is a common JS term
    key_lower = key.lower()
    for term in common_js_terms:
        if term in key_lower:
            return True
            
    return False

def extract_api_keys(text):
    """
    Extract potential API keys from text
    
    Args:
        text: The text to parse
        
    Returns:
        dict: A dictionary of potential API keys by type
    """
    if not text:
        return {}
        
    api_keys = {
        "generic": [],
        "aws": [],
        "google": [],
        "github": [],
        "stripe": [],
        "mailchimp": [],
        "slack": []
    }
    
    # Skip extraction if the text is just HTML with no actual API keys
    if "<!DOCTYPE" in text and "<html" in text and "<head" in text and "<body" in text:
        # Check if it's a standard HTML page with common JavaScript libraries
        if re.search(r'<script\s+src=[\'"](?:https?:)?//(?:code\.jquery\.com|cdn\.jsdelivr\.net|stackpath\.bootstrapcdn\.com)', text):
            # This is likely just a standard web page with common libraries, not containing real API keys
            return api_keys
    
    # Generic API key pattern - more specific to avoid false positives
    # Look for keys in common API key contexts
    generic_patterns = [
        r'api[_\-]?key[\'"\s:=]+([\'"])([a-zA-Z0-9_\-\.]{16,64})(\1)',  # api_key="KEY"
        r'auth[_\-]?token[\'"\s:=]+([\'"])([a-zA-Z0-9_\-\.]{16,64})(\1)',  # auth_token="KEY"
        r'access[_\-]?token[\'"\s:=]+([\'"])([a-zA-Z0-9_\-\.]{16,64})(\1)',  # access_token="KEY"
        r'secret[_\-]?key[\'"\s:=]+([\'"])([a-zA-Z0-9_\-\.]{16,64})(\1)',  # secret_key="KEY"
        r'client[_\-]?secret[\'"\s:=]+([\'"])([a-zA-Z0-9_\-\.]{16,64})(\1)',  # client_secret="KEY"
        r'password[\'"\s:=]+([\'"])([a-zA-Z0-9_\-\.]{16,64})(\1)'  # password="KEY"
    ]
    
    for pattern in generic_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            if len(match) >= 3:  # Make sure we have the value (should be in group 2)
                key = match[1]
                if key not in api_keys["generic"] and not _is_common_js_variable(key):
                    api_keys["generic"].append(key)
    
    # Also look for standalone keys that match common API key formats
    standalone_pattern = r'[\'"]([a-zA-Z0-9_\-]{32,64})[\'"]'
    standalone_matches = re.findall(standalone_pattern, text)
    for key in standalone_matches:
        # Only include if it looks like a real API key (has mixed case, numbers, etc.)
        if (re.search(r'[A-Z]', key) and re.search(r'[a-z]', key) and 
            re.search(r'[0-9]', key) and not _is_common_js_variable(key)):
            if key not in api_keys["generic"]:
                api_keys["generic"].append(key)
    
    # AWS Access Key
    aws_pattern = r'AKIA[0-9A-Z]{16}'
    aws_matches = re.findall(aws_pattern, text)
    for match in aws_matches:
        if match not in api_keys["aws"]:
            api_keys["aws"].append(match)
    
    # Google API Key
    google_pattern = r'AIza[0-9A-Za-z_-]{35}'
    google_matches = re.findall(google_pattern, text)
    for match in google_matches:
        if match not in api_keys["google"]:
            api_keys["google"].append(match)
    
    # GitHub Token
    github_pattern = r'gh[pousr]_[0-9a-zA-Z]{36}'
    github_matches = re.findall(github_pattern, text)
    for match in github_matches:
        if match not in api_keys["github"]:
            api_keys["github"].append(match)
    
    # Stripe API Key
    stripe_pattern = r'sk_live_[0-9a-zA-Z]{24}'
    stripe_matches = re.findall(stripe_pattern, text)
    for match in stripe_matches:
        if match not in api_keys["stripe"]:
            api_keys["stripe"].append(match)
    
    # Mailchimp API Key
    mailchimp_pattern = r'[0-9a-zA-Z]{32}-us[0-9]{1,2}'
    mailchimp_matches = re.findall(mailchimp_pattern, text)
    for match in mailchimp_matches:
        if match not in api_keys["mailchimp"]:
            api_keys["mailchimp"].append(match)
    
    # Slack Token
    slack_pattern = r'xox[baprs]-[0-9a-zA-Z]{10,48}'
    slack_matches = re.findall(slack_pattern, text)
    for match in slack_matches:
        if match not in api_keys["slack"]:
            api_keys["slack"].append(match)
    
    # Remove empty categories
    return {k: v for k, v in api_keys.items() if v}

def extract_tokens(text):
    """
    Extract potential authentication tokens from text
    
    Args:
        text: The text to parse
        
    Returns:
        dict: A dictionary of potential tokens by type
    """
    if not text:
        return {}
        
    tokens = {
        "jwt": [],
        "oauth": [],
        "session": [],
        "csrf": []
    }
    
    # JWT Token
    jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    jwt_matches = re.findall(jwt_pattern, text)
    for match in jwt_matches:
        if match not in tokens["jwt"]:
            tokens["jwt"].append(match)
    
    # OAuth Token
    oauth_pattern = r'[\'"]?access_token[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9._-]+)[\'"]'
    oauth_matches = re.finditer(oauth_pattern, text)
    for match in oauth_matches:
        token = match.group(1)
        if token not in tokens["oauth"]:
            tokens["oauth"].append(token)
    
    # Session Token
    session_pattern = r'[\'"]?session[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9._-]+)[\'"]'
    session_matches = re.finditer(session_pattern, text)
    for match in session_matches:
        token = match.group(1)
        if token not in tokens["session"]:
            tokens["session"].append(token)
    
    # CSRF Token
    csrf_pattern = r'[\'"]?csrf[_-]?token[\'"]?\s*[:=]\s*[\'"]([a-zA-Z0-9._-]+)[\'"]'
    csrf_matches = re.finditer(csrf_pattern, text)
    for match in csrf_matches:
        token = match.group(1)
        if token not in tokens["csrf"]:
            tokens["csrf"].append(token)
    
    # Remove empty categories
    return {k: v for k, v in tokens.items() if v}