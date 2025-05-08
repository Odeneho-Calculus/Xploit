#!/usr/bin/env python3
"""
setup_realtime.py - Setup script for real-time data retrieval capabilities
"""

import os
import sys
import subprocess
import argparse
import platform
from pathlib import Path

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="XPLOIT Real-time Data Retrieval Setup",
        epilog="Example: python setup_realtime.py --all"
    )
    
    parser.add_argument("--all", action="store_true", help="Install all dependencies")
    parser.add_argument("--basic", action="store_true", help="Install basic dependencies only")
    parser.add_argument("--databases", action="store_true", help="Install database connectors")
    parser.add_argument("--visualization", action="store_true", help="Install data visualization libraries")
    parser.add_argument("--api", action="store_true", help="Install API-related libraries")
    parser.add_argument("--websockets", action="store_true", help="Install WebSocket libraries")
    parser.add_argument("--no-confirm", action="store_true", help="Skip confirmation prompts")
    
    return parser.parse_args()

def install_packages(packages, description):
    """
    Install Python packages using pip
    
    Args:
        packages: List of packages to install
        description: Description of the package group
    """
    print(f"\n[*] Installing {description}...")
    
    for package in packages:
        print(f"    - {package}")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + packages)
        print(f"[+] Successfully installed {description}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error installing {description}: {e}")
        return False

def main():
    """Main entry point for the setup script"""
    args = parse_arguments()
    
    # Print banner
    print("""
 __   __      _       _ _   
 \ \ / /     | |     (_) |  
  \ V / _ __ | | ___  _| |_ 
   > < | '_ \| |/ _ \| | __|
  / . \| |_) | | (_) | | |_ 
 /_/ \_\ .__/|_|\___/|_|\__|
       | |                  
       |_|                  
    """)
    print("XPLOIT Real-time Data Retrieval Setup")
    print("=====================================\n")
    
    # Check if any options were specified
    if not (args.all or args.basic or args.databases or args.visualization or args.api or args.websockets):
        args.all = True
        print("[*] No options specified, installing all dependencies")
    
    # Define package groups
    basic_packages = [
        "requests>=2.28.1",
        "httpx>=0.23.0",
        "aiohttp>=3.8.3",
        "websockets>=10.4",
        "pyyaml>=6.0",
        "rich>=12.6.0",
        "colorama>=0.4.5",
        "tqdm>=4.64.0",
        "python-dotenv>=0.21.0",
        "pydantic>=1.10.2"
    ]
    
    database_packages = [
        "pymysql>=1.0.2",
        "psycopg2-binary>=2.9.5",
        "oracledb>=1.3.1",
        "sqlalchemy>=2.0.7",
        "redis>=4.5.1",
        "elasticsearch>=8.6.2",
        "pymongo>=4.3.3"
    ]
    
    # Add pyodbc only on Windows and Linux
    if platform.system() in ["Windows", "Linux"]:
        database_packages.append("pyodbc>=4.0.35")
    
    visualization_packages = [
        "pandas>=1.5.3",
        "numpy>=1.24.2",
        "matplotlib>=3.7.1",
        "seaborn>=0.12.2",
        "plotly>=5.13.1",
        "dash>=2.9.1"
    ]
    
    api_packages = [
        "fastapi>=0.95.0",
        "uvicorn>=0.21.1",
        "graphene>=3.2.1",
        "grpcio>=1.53.0",
        "protobuf>=4.22.1"
    ]
    
    websocket_packages = [
        "websockets>=10.4",
        "aiokafka>=0.8.0",
        "confluent-kafka>=2.0.2"
    ]
    
    # Determine which packages to install
    packages_to_install = []
    
    if args.all or args.basic:
        packages_to_install.extend(basic_packages)
    
    if args.all or args.databases:
        packages_to_install.extend(database_packages)
    
    if args.all or args.visualization:
        packages_to_install.extend(visualization_packages)
    
    if args.all or args.api:
        packages_to_install.extend(api_packages)
    
    if args.all or args.websockets:
        packages_to_install.extend(websocket_packages)
    
    # Remove duplicates
    packages_to_install = list(set(packages_to_install))
    
    # Confirm installation
    if not args.no_confirm:
        print(f"[*] The following packages will be installed:")
        for package in packages_to_install:
            print(f"    - {package}")
        
        confirm = input("\n[?] Do you want to continue? (y/n): ")
        if confirm.lower() not in ["y", "yes"]:
            print("[-] Installation cancelled")
            return 1
    
    # Install packages
    success = install_packages(packages_to_install, "dependencies")
    
    if success:
        # Create config directory if it doesn't exist
        config_dir = Path("config")
        if not config_dir.exists():
            config_dir.mkdir()
            print("[+] Created config directory")
        
        # Create default configuration file if it doesn't exist
        config_file = config_dir / "realtime.yaml"
        if not config_file.exists():
            # Check if the file exists in the repository
            repo_config_file = Path("config/realtime.yaml")
            if repo_config_file.exists():
                # Copy the file
                with open(repo_config_file, "r") as src, open(config_file, "w") as dst:
                    dst.write(src.read())
                print("[+] Copied default configuration file")
            else:
                # Create a minimal configuration file
                with open(config_file, "w") as f:
                    f.write("""# Real-time data sources configuration

# API endpoints for polling
apis:
  - name: "example_api"
    url: "https://api.example.com"
    method: "GET"
    headers:
      User-Agent: "XPLOIT Security Scanner"
    params:
      key: "YOUR_API_KEY"  # Replace with your actual API key
    interval: 300  # 5 minutes

# WebSocket connections for real-time data
websockets:
  - name: "example_websocket"
    url: "wss://api.example.com/ws"
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
  - name: "example_log"
    path: "/var/log/example.log"
    patterns:
      - "(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+).*\\[(?P<timestamp>.*?)\\]\\s+\"(?P<method>\\w+)\\s+(?P<url>.*?)\\s+HTTP.*?\"\\s+(?P<status>\\d+)"
""")
                print("[+] Created default configuration file")
        
        print("\n[+] Setup completed successfully")
        print("[*] You can now use the real-time data retrieval capabilities:")
        print("    python -m xploit.main realtime --help")
        
        return 0
    else:
        print("\n[-] Setup failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())