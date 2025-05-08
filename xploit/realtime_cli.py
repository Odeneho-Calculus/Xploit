#!/usr/bin/env python3
"""
xploit/realtime_cli.py - Command-line interface for real-time data retrieval
"""

import os
import sys
import time
import json
import logging
import argparse
from typing import Dict, List, Any, Optional
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import print as rprint

from xploit import __version__
from xploit.utils.helpers import setup_logging
from xploit.utils.realtime_config import RealtimeConfig
from xploit.modules.realtime_data import RealtimeDataRetriever

# Set up logger
logger = logging.getLogger("xploit.realtime_cli")
console = Console()

# Global variables
data_buffer = []
data_buffer_max_size = 100
live_display = None
layout = None

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="XPLOIT Real-time Data Retrieval Tool",
        epilog="Example: xploit-realtime --config config/realtime.yaml --api shodan"
    )
    
    parser.add_argument("--config", "-c", default="config/realtime.yaml",
                        help="Path to the configuration file (default: config/realtime.yaml)")
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument("--format", "-f", default="json", choices=["json", "csv", "sqlite"],
                        help="Output format (default: json)")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress normal output")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--version", action="version", version=f"XPLOIT {__version__}")
    
    # Data source options
    source_group = parser.add_argument_group("Data Source Options")
    source_group.add_argument("--api", help="API name to use from configuration")
    source_group.add_argument("--websocket", help="WebSocket name to use from configuration")
    source_group.add_argument("--database", help="Database name to use from configuration")
    source_group.add_argument("--log", help="Log name to use from configuration")
    source_group.add_argument("--all", action="store_true", help="Use all configured data sources")
    
    # API options
    api_group = parser.add_argument_group("API Options")
    api_group.add_argument("--api-endpoint", help="API endpoint to query")
    api_group.add_argument("--api-method", default="GET", choices=["GET", "POST", "PUT", "DELETE"],
                          help="API method (default: GET)")
    api_group.add_argument("--api-params", help="API query parameters (JSON string)")
    api_group.add_argument("--api-data", help="API request data (JSON string)")
    
    # WebSocket options
    ws_group = parser.add_argument_group("WebSocket Options")
    ws_group.add_argument("--ws-message", help="Message to send to WebSocket (JSON string)")
    
    # Database options
    db_group = parser.add_argument_group("Database Options")
    db_group.add_argument("--db-query", help="Custom database query")
    
    # Runtime options
    runtime_group = parser.add_argument_group("Runtime Options")
    runtime_group.add_argument("--duration", "-d", type=int, default=0,
                              help="Duration to run in seconds (0 = indefinite)")
    runtime_group.add_argument("--buffer-size", type=int, default=100,
                              help="Maximum number of data points to keep in memory (default: 100)")
    
    return parser.parse_args()

def data_callback(data: Dict[str, Any]) -> None:
    """
    Callback function for real-time data updates
    
    Args:
        data: Data from the real-time source
    """
    global data_buffer
    
    # Add the data to the buffer
    data_buffer.append(data)
    
    # Trim the buffer if it exceeds the maximum size
    if len(data_buffer) > data_buffer_max_size:
        data_buffer = data_buffer[-data_buffer_max_size:]
    
    # Log the data
    logger.debug(f"Received data from {data.get('source')}: {data.get('name')}")
    
    # Update the display
    update_display()
    
    # Write to output file if specified
    if args.output:
        write_to_output(data)

def write_to_output(data: Dict[str, Any]) -> None:
    """
    Write data to the output file
    
    Args:
        data: Data to write
    """
    try:
        if args.format == "json":
            with open(args.output, "a") as f:
                f.write(json.dumps(data) + "\n")
        elif args.format == "csv":
            import csv
            
            # Flatten the data
            flat_data = flatten_dict(data)
            
            # Check if the file exists
            file_exists = os.path.isfile(args.output)
            
            with open(args.output, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=flat_data.keys())
                
                # Write the header if the file is new
                if not file_exists:
                    writer.writeheader()
                
                writer.writerow(flat_data)
        elif args.format == "sqlite":
            import sqlite3
            
            # Connect to the database
            conn = sqlite3.connect(args.output)
            cursor = conn.cursor()
            
            # Create the table if it doesn't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS realtime_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                name TEXT,
                timestamp REAL,
                data TEXT
            )
            ''')
            
            # Insert the data
            cursor.execute(
                "INSERT INTO realtime_data (source, name, timestamp, data) VALUES (?, ?, ?, ?)",
                (data.get("source"), data.get("name"), data.get("timestamp"), json.dumps(data.get("data")))
            )
            
            # Commit and close
            conn.commit()
            conn.close()
    
    except Exception as e:
        logger.error(f"Error writing to output file: {str(e)}")

def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = "_") -> Dict[str, Any]:
    """
    Flatten a nested dictionary
    
    Args:
        d: Dictionary to flatten
        parent_key: Parent key for nested dictionaries
        sep: Separator for keys
        
    Returns:
        Flattened dictionary
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            items.append((new_key, json.dumps(v)))
        else:
            items.append((new_key, v))
    
    return dict(items)

def create_layout() -> Layout:
    """
    Create the layout for the live display
    
    Returns:
        Layout object
    """
    layout = Layout()
    
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=3)
    )
    
    layout["main"].split_row(
        Layout(name="data_sources", ratio=1),
        Layout(name="data_feed", ratio=2)
    )
    
    return layout

def update_display() -> None:
    """Update the live display with the latest data"""
    global layout
    
    if not layout:
        return
    
    # Update the header
    header_text = Text("XPLOIT Real-time Data Retrieval", style="bold blue")
    header_text.append(f" v{__version__}", style="dim")
    layout["header"].update(Panel(header_text, border_style="blue"))
    
    # Update the data sources panel
    sources_table = Table(show_header=True, header_style="bold")
    sources_table.add_column("Type")
    sources_table.add_column("Name")
    sources_table.add_column("Status")
    
    for source_type in ["api", "websocket", "database", "log"]:
        for source in getattr(config, f"get_all_{source_type}s")():
            name = source.get("name", "unnamed")
            status = "[green]Active" if name in active_sources else "[red]Inactive"
            sources_table.add_row(source_type.capitalize(), name, status)
    
    layout["data_sources"].update(Panel(sources_table, title="Data Sources", border_style="green"))
    
    # Update the data feed panel
    data_table = Table(show_header=True, header_style="bold")
    data_table.add_column("Time")
    data_table.add_column("Source")
    data_table.add_column("Name")
    data_table.add_column("Data")
    
    for data in reversed(data_buffer[-10:]):  # Show the last 10 data points
        timestamp = time.strftime("%H:%M:%S", time.localtime(data.get("timestamp", 0)))
        source = data.get("source", "unknown")
        name = data.get("name", "unnamed")
        
        # Format the data
        data_str = str(data.get("data", ""))
        if len(data_str) > 50:
            data_str = data_str[:47] + "..."
        
        data_table.add_row(timestamp, source, name, data_str)
    
    layout["data_feed"].update(Panel(data_table, title="Data Feed", border_style="yellow"))
    
    # Update the footer
    footer_text = Text(f"Data points: {len(data_buffer)}/{data_buffer_max_size}")
    if args.duration > 0:
        elapsed = time.time() - start_time
        remaining = max(0, args.duration - elapsed)
        footer_text.append(f" | Time remaining: {int(remaining)}s")
    
    layout["footer"].update(Panel(footer_text, border_style="blue"))

def print_banner():
    """Print the XPLOIT tool banner"""
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
    rprint(f"[bold yellow]XPLOIT v{__version__}[/bold yellow]: [italic]Real-time Data Retrieval Tool[/italic]")
    rprint("[dim]Developed by Security Researchers[/dim]\n")

def main():
    """Main entry point for the XPLOIT real-time data retrieval tool"""
    global args, config, data_buffer_max_size, start_time, active_sources, layout, live_display
    
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
            print_banner()
        
        # Set the buffer size
        data_buffer_max_size = args.buffer_size
        
        # Load the configuration
        config = RealtimeConfig(args.config)
        config_data = config.load()
        
        if not config_data:
            logger.error(f"Failed to load configuration from {args.config}")
            return 1
        
        # Create the real-time data retriever
        retriever = RealtimeDataRetriever(config=config_data, callback=data_callback)
        
        # Track active sources
        active_sources = set()
        
        # Set up the live display
        if not args.quiet:
            layout = create_layout()
            live_display = Live(layout, refresh_per_second=4)
            live_display.start()
        
        # Start the data retrieval
        if args.api:
            # Use a specific API
            api_config = config.get_api(args.api)
            if not api_config:
                logger.error(f"API configuration not found: {args.api}")
                return 1
            
            # Check if we should make a one-time query
            if args.api_endpoint:
                # Parse the parameters and data
                params = None
                data = None
                
                if args.api_params:
                    try:
                        params = json.loads(args.api_params)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid API parameters JSON: {args.api_params}")
                        return 1
                
                if args.api_data:
                    try:
                        data = json.loads(args.api_data)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid API data JSON: {args.api_data}")
                        return 1
                
                # Make the query
                result = retriever.query_api(
                    api_name=args.api,
                    endpoint=args.api_endpoint,
                    method=args.api_method,
                    params=params,
                    data=data
                )
                
                # Process the result
                if "error" in result:
                    logger.error(f"API query error: {result['error']}")
                    return 1
                
                # Call the callback with the result
                data_callback({
                    "source": "api",
                    "name": args.api,
                    "timestamp": time.time(),
                    "data": result
                })
                
                # Print the result
                if not args.quiet:
                    rprint(f"\n[bold green]API Query Result:[/bold green]")
                    rprint(result)
                
                # Exit if we're not starting real-time monitoring
                if not args.all:
                    return 0
            
            # Start real-time monitoring
            active_sources.add(args.api)
        
        if args.websocket:
            # Use a specific WebSocket
            ws_config = config.get_websocket(args.websocket)
            if not ws_config:
                logger.error(f"WebSocket configuration not found: {args.websocket}")
                return 1
            
            # Check if we should send a message
            if args.ws_message:
                try:
                    message = json.loads(args.ws_message)
                except json.JSONDecodeError:
                    logger.error(f"Invalid WebSocket message JSON: {args.ws_message}")
                    return 1
                
                # TODO: Implement WebSocket message sending
                logger.warning("WebSocket message sending not implemented yet")
            
            active_sources.add(args.websocket)
        
        if args.database:
            # Use a specific database
            db_config = config.get_database(args.database)
            if not db_config:
                logger.error(f"Database configuration not found: {args.database}")
                return 1
            
            # Check if we should make a one-time query
            if args.db_query:
                # Make the query
                result = retriever.query_database(
                    db_name=args.database,
                    query=args.db_query
                )
                
                # Process the result
                if result and "error" in result[0]:
                    logger.error(f"Database query error: {result[0]['error']}")
                    return 1
                
                # Call the callback with the result
                data_callback({
                    "source": "database",
                    "name": args.database,
                    "timestamp": time.time(),
                    "data": result
                })
                
                # Print the result
                if not args.quiet:
                    rprint(f"\n[bold green]Database Query Result:[/bold green]")
                    rprint(result)
                
                # Exit if we're not starting real-time monitoring
                if not args.all:
                    return 0
            
            active_sources.add(args.database)
        
        if args.log:
            # Use a specific log
            log_config = config.get_log(args.log)
            if not log_config:
                logger.error(f"Log configuration not found: {args.log}")
                return 1
            
            active_sources.add(args.log)
        
        # Use all configured data sources if requested
        if args.all:
            for api in config.get_all_apis():
                active_sources.add(api["name"])
            
            for ws in config.get_all_websockets():
                active_sources.add(ws["name"])
            
            for db in config.get_all_databases():
                active_sources.add(db["name"])
            
            for log in config.get_all_logs():
                active_sources.add(log["name"])
        
        # Start the data retrieval
        if not retriever.start():
            logger.error("Failed to start real-time data retrieval")
            return 1
        
        # Record the start time
        start_time = time.time()
        
        try:
            # Run for the specified duration
            if args.duration > 0:
                time.sleep(args.duration)
            else:
                # Run indefinitely
                while True:
                    time.sleep(1)
        
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        
        finally:
            # Stop the data retrieval
            retriever.stop()
            
            # Stop the live display
            if live_display:
                live_display.stop()
            
            # Print a summary
            if not args.quiet:
                rprint(f"\n[bold green]Data Retrieval Summary:[/bold green]")
                rprint(f"Data points collected: {len(data_buffer)}")
                rprint(f"Duration: {time.time() - start_time:.2f} seconds")
                
                if args.output:
                    rprint(f"Output saved to: {args.output}")
        
        return 0
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())