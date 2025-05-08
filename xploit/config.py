"""
Configuration settings for the XPLOIT tool.
"""

import os
from pathlib import Path
import logging
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

# Base directories
BASE_DIR = Path(__file__).parent.parent.absolute()
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = DATA_DIR / "output"

# Create directories if they don't exist
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# HTTP Configuration
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DEFAULT_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
REQUEST_DELAY = 0.5  # seconds between requests

# Threading configuration
DEFAULT_THREADS = 5
MAX_THREADS = 20

# SQLi Payloads
SQLI_PAYLOADS = [
    "'",
    "\"",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' OR 1=1 -- -",
    "\" OR 1=1 -- -",
    "' OR '1'='1' -- -",
    "\" OR \"1\"=\"1\" -- -",
    "' AND 1=1 -- -",
    "' AND 1=2 -- -",
    "1' AND SLEEP(5) -- -",
    "1' AND IF(1=1, SLEEP(5), 0) -- -",
]

# IDOR testing configuration
IDOR_RANGE_DEFAULT = 100  # How many IDs to check before and after the provided ID
IDOR_BATCH_SIZE = 20      # How many requests to process in one batch

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = OUTPUT_DIR / "xploit.log"

# Set up logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Database configuration
DB_PATH = OUTPUT_DIR / "results.db"

# Export formats
EXPORT_FORMATS = ["json", "csv", "html", "sqlite"]
DEFAULT_EXPORT_FORMAT = "json"