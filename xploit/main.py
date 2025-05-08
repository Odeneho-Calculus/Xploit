#!/usr/bin/env python3
"""
xploit/main.py - Main entry point for the XPLOIT tool

This module coordinates the execution of all components in the XPLOIT tool,
handling command-line arguments, configuration, and the overall workflow.
"""

import sys
import time
import logging
import argparse
import os
import json
from urllib.parse import urlparse, parse_qs
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import print as rprint

from xploit import __version__
from xploit.core.engine import XploitEngine
from xploit.utils.helpers import setup_logging, validate_url
from xploit.run_modes import run_standard_mode, run_realtime_mode

# Set up logger
logger = logging.getLogger("xploit.main")
console = Console()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="XPLOIT: Targeted Database Enumeration via Parameter Injection",
        epilog="Example: xploit --url 'https://example.com/page.php?id=123' --param 'id'"
    )
    
    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")
    
    # Standard mode parser (default)
    std_parser = subparsers.add_parser("standard", help="Standard vulnerability scanning mode")
    std_parser.add_argument("--url", "-u", required=True, help="Target URL with parameter")
    std_parser.add_argument("--param", "-p", help="Parameter to test (default: auto-detect)")
    std_parser.add_argument("--threads", "-t", type=int, default=5, help="Number of threads (default: 5)")
    std_parser.add_argument("--delay", "-d", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    std_parser.add_argument("--output", "-o", help="Output file for results")
    std_parser.add_argument("--format", "-f", default="json", choices=["json", "csv", "html", "sqlite"],
                        help="Output format (default: json)")
    std_parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    std_parser.add_argument("--quiet", "-q", action="store_true", help="Suppress normal output")
    std_parser.add_argument("--no-color", action="store_true", help="Disable color output")
    
    # Testing options for standard mode
    std_testing_group = std_parser.add_argument_group("Testing Options")
    std_testing_group.add_argument("--sqli", action="store_true", help="Test for SQL injection")
    std_testing_group.add_argument("--idor", action="store_true", help="Test for IDOR vulnerabilities")
    std_testing_group.add_argument("--idor-range", type=int, default=100, 
                               help="Range to test for IDOR (+/- from current ID, default: 100)")
    
    # Advanced options for standard mode
    std_adv_group = std_parser.add_argument_group("Advanced Options")
    std_adv_group.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    std_adv_group.add_argument("--user-agent", help="Custom User-Agent string")
    std_adv_group.add_argument("--cookies", help="Cookies to include with requests (format: name=value; name2=value2)")
    std_adv_group.add_argument("--headers", help="Custom headers (format: header1:value1;header2:value2)")
    std_adv_group.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    std_adv_group.add_argument("--auth", help="Basic authentication (username:password)")
    
    # Real-time mode parser
    rt_parser = subparsers.add_parser("realtime", help="Real-time data retrieval mode")
    rt_parser.add_argument("--config", "-c", default="config/realtime.yaml",
                        help="Path to the configuration file (default: config/realtime.yaml)")
    rt_parser.add_argument("--output", "-o", help="Output file for results")
    rt_parser.add_argument("--format", "-f", default="json", choices=["json", "csv", "sqlite"],
                        help="Output format (default: json)")
    rt_parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    rt_parser.add_argument("--quiet", "-q", action="store_true", help="Suppress normal output")
    rt_parser.add_argument("--no-color", action="store_true", help="Disable color output")
    
    # Data source options for real-time mode
    rt_source_group = rt_parser.add_argument_group("Data Source Options")
    rt_source_group.add_argument("--api", help="API name to use from configuration")
    rt_source_group.add_argument("--websocket", help="WebSocket name to use from configuration")
    rt_source_group.add_argument("--database", help="Database name to use from configuration")
    rt_source_group.add_argument("--log", help="Log name to use from configuration")
    rt_source_group.add_argument("--all", action="store_true", help="Use all configured data sources")
    
    # API options for real-time mode
    rt_api_group = rt_parser.add_argument_group("API Options")
    rt_api_group.add_argument("--api-endpoint", help="API endpoint to query")
    rt_api_group.add_argument("--api-method", default="GET", choices=["GET", "POST", "PUT", "DELETE"],
                          help="API method (default: GET)")
    rt_api_group.add_argument("--api-params", help="API query parameters (JSON string)")
    rt_api_group.add_argument("--api-data", help="API request data (JSON string)")
    
    # Runtime options for real-time mode
    rt_runtime_group = rt_parser.add_argument_group("Runtime Options")
    rt_runtime_group.add_argument("--duration", type=int, default=0,
                              help="Duration to run in seconds (0 = indefinite)")
    rt_runtime_group.add_argument("--buffer-size", type=int, default=100,
                              help="Maximum number of data points to keep in memory (default: 100)")
    
    # Add version argument to the main parser
    parser.add_argument("--version", action="version", version=f"XPLOIT {__version__}")
    
    args = parser.parse_args()
    
    # If no mode is specified, default to standard mode
    if args.mode is None:
        args.mode = "standard"
        
        # Check if any real-time specific arguments were provided
        rt_args = ["config", "api", "websocket", "database", "log", "all", 
                  "api_endpoint", "api_method", "api_params", "api_data", 
                  "duration", "buffer_size"]
        
        for arg in rt_args:
            if hasattr(args, arg) and getattr(args, arg) is not None:
                logger.warning(f"Real-time argument --{arg.replace('_', '-')} ignored in standard mode")
    
    return args

# Extract param function moved to run_modes.py

def print_banner(mode="standard"):
    """
    Print the XPLOIT tool banner
    
    Args:
        mode: Operation mode (standard or realtime)
    """
    banner = r"""
 __   __      _       _ _   
 \ \ / /     | |     (_) |  
  \ V / _ __ | | ___  _| |_ 
   > < | '_ \| |/ _ \| | __|
  / . \| |_) | | (_) | | |_ 
 /_/ \_\ .__/|_|\___/|_|\__|
       | |                  
       |_|                  
    """
    
    rprint(f"[bold blue]{banner}[/bold blue]")
    
    if mode == "standard":
        rprint(f"[bold yellow]XPLOIT v{__version__}[/bold yellow]: [italic]Targeted Database Enumeration Tool[/italic]")
    elif mode == "realtime":
        rprint(f"[bold yellow]XPLOIT v{__version__}[/bold yellow]: [italic]Real-time Data Retrieval Tool[/italic]")
    else:
        rprint(f"[bold yellow]XPLOIT v{__version__}[/bold yellow]")
    
    rprint("[dim]Developed by Security Researchers[/dim]\n")

def main():
    """Main entry point for the XPLOIT tool"""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Set up logging based on verbosity
        log_level = logging.WARNING
        if args.verbose == 1:
            log_level = logging.INFO
        elif args.verbose >= 2:
            log_level = logging.DEBUG
        
        setup_logging(log_level, args.no_color)
        
        if not args.quiet:
            print_banner(args.mode)
        
        # Run the appropriate mode
        if args.mode == "standard":
            return run_standard_mode(args)
        elif args.mode == "realtime":
            return run_realtime_mode(args)
        else:
            logger.error(f"Unknown mode: {args.mode}")
            return 1
        
        # Start the testing process with progress reporting
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            disable=args.quiet
        ) as progress:
            # Run the engine
            result = engine.run(progress)
        
        # Display summary
        if not args.quiet and result:
            rprint("\n[bold green]Scan Complete![/bold green]")
            rprint(f"[bold]Target:[/bold] {args.url}")
            rprint(f"[bold]Parameter:[/bold] {target_param}")
            
            vulnerabilities = result.get("vulnerabilities", [])
            if vulnerabilities:
                rprint(f"\n[bold red]Found {len(vulnerabilities)} potential vulnerabilities:[/bold red]")
                for i, vuln in enumerate(vulnerabilities, 1):
                    vuln_type = vuln.get('type', 'Unknown')
                    vuln_desc = vuln.get('description', 'No description available')
                    rprint(f"  [bold]{i}.[/bold] [yellow]{vuln_type}[/yellow]: {vuln_desc}")
                    
                    if 'evidence' in vuln and vuln['evidence']:
                        evidence = vuln['evidence']
                        if isinstance(evidence, str):
                            rprint(f"     [dim]Evidence: {evidence[:100]}...[/dim]")
                        else:
                            rprint(f"     [dim]Evidence found[/dim]")
            else:
                rprint("\n[bold green]No obvious vulnerabilities detected.[/bold green]")
            
            # Display extracted data in a more detailed way
            extracted_data = result.get("extracted_data", {})
            if extracted_data:
                rprint("\n[bold blue]===== EXTRACTED DATA =====[/bold blue]")
                
                # SQL Injection Data
                sql_data = extracted_data.get("sql_injection_data", {})
                if sql_data:
                    rprint("\n[bold green]Database Information:[/bold green]")
                    
                    # Version info
                    if "version" in sql_data:
                        rprint("\n[bold]Database Version:[/bold]")
                        for item in sql_data["version"]:
                            rprint(f"  • {item['data'][0] if item['data'] else 'Unknown'}")
                    
                    # Database name
                    if "database" in sql_data:
                        rprint("\n[bold]Database Name:[/bold]")
                        for item in sql_data["database"]:
                            rprint(f"  • {item['data'][0] if item['data'] else 'Unknown'}")
                    
                    # Tables
                    if "tables" in sql_data:
                        rprint("\n[bold]Database Tables:[/bold]")
                        for item in sql_data["tables"]:
                            if item['data']:
                                tables = item['data'][0].split(',')
                                for table in tables[:20]:  # Limit to first 20 tables
                                    rprint(f"  • {table}")
                                if len(tables) > 20:
                                    rprint(f"  • ... and {len(tables) - 20} more tables")
                    
                    # User tables
                    if "user_tables" in sql_data:
                        rprint("\n[bold]User-Related Tables:[/bold]")
                        for item in sql_data["user_tables"]:
                            if item['data']:
                                tables = item['data'][0].split(',')
                                for table in tables:
                                    rprint(f"  • {table}")
                    
                    # User columns
                    if "user_columns" in sql_data:
                        rprint("\n[bold]User Table Columns:[/bold]")
                        for item in sql_data["user_columns"]:
                            if item['data']:
                                columns = item['data'][0].split(',')
                                for column in columns:
                                    rprint(f"  • {column}")
                    
                    # Credentials and user data
                    credential_keys = ["credentials", "usernames", "emails", "moodle_credentials", 
                                      "moodle_usernames", "moodle_emails", "moodle_user_details"]
                    
                    has_credentials = any(key in sql_data for key in credential_keys)
                    if has_credentials:
                        rprint("\n[bold red]User Credentials and Data:[/bold red]")
                        
                        for key in credential_keys:
                            if key in sql_data:
                                rprint(f"\n[bold]{key.replace('_', ' ').title()}:[/bold]")
                                for item in sql_data[key]:
                                    if item['data']:
                                        data_items = item['data'][0].split(',')
                                        for data_item in data_items[:20]:  # Limit to first 20 items
                                            rprint(f"  • {data_item}")
                                        if len(data_items) > 20:
                                            rprint(f"  • ... and {len(data_items) - 20} more items")
                    
                    # Quiz data
                    quiz_keys = ["quiz_names", "quiz_questions", "quiz_answers", "target_quiz", "target_quiz_questions"]
                    has_quiz_data = any(key in sql_data for key in quiz_keys)
                    
                    if has_quiz_data:
                        rprint("\n[bold magenta]Quiz Data:[/bold magenta]")
                        
                        for key in quiz_keys:
                            if key in sql_data:
                                rprint(f"\n[bold]{key.replace('_', ' ').title()}:[/bold]")
                                for item in sql_data[key]:
                                    if item['data']:
                                        data_items = item['data'][0].split(',')
                                        for data_item in data_items[:10]:  # Limit to first 10 items
                                            rprint(f"  • {data_item}")
                                        if len(data_items) > 10:
                                            rprint(f"  • ... and {len(data_items) - 10} more items")
                
                # Base data extraction
                base_data = extracted_data.get("base_data", {})
                if base_data:
                    sensitive_data_found = False
                    
                    for key in ["emails", "phone_numbers", "credit_cards", "api_keys", "tokens"]:
                        if base_data.get(key):
                            if not sensitive_data_found:
                                rprint("\n[bold yellow]Sensitive Information Found:[/bold yellow]")
                                sensitive_data_found = True
                            
                            rprint(f"\n[bold]{key.replace('_', ' ').title()}:[/bold]")
                            items = base_data[key]
                            # Handle both list and non-list types
                            if isinstance(items, list):
                                display_items = items[:10]  # Limit to first 10 items
                                for item in display_items:
                                    rprint(f"  • {item}")
                                if len(items) > 10:
                                    rprint(f"  • ... and {len(items) - 10} more items")
                            else:
                                # Handle non-list items (like dictionaries)
                                rprint(f"  • {items}")
            
            # If no data was extracted
            if not extracted_data or (not extracted_data.get("sql_injection_data") and not extracted_data.get("base_data")):
                rprint("\n[bold yellow]No database data could be extracted.[/bold yellow]")
                rprint("[dim]This could be due to insufficient permissions, WAF protection, or false positive detection.[/dim]")
                
            if args.output:
                rprint(f"\n[bold]Results saved to:[/bold] {args.output}")
                rprint("[dim]The output file contains all raw data that was collected.[/dim]")
        
        return 0
    
    except KeyboardInterrupt:
        rprint("\n[bold red]Operation cancelled by user[/bold red]")
        return 130
    except Exception as e:
        logger.exception("An unexpected error occurred:")
        rprint(f"[bold red]Error:[/bold red] {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())