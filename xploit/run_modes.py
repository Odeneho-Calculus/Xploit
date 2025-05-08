"""
xploit/run_modes.py - Run modes for the XPLOIT tool
"""

import os
import sys
import time
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import print as rprint

from xploit import __version__
from xploit.core.engine import XploitEngine
from xploit.utils.helpers import validate_url

# Set up logger
logger = logging.getLogger("xploit.run_modes")
console = Console()

def extract_param_from_url(url):
    """Extract the first parameter from a URL if no specific parameter is provided"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return None
    
    # Return the first parameter found
    return list(query_params.keys())[0]

def run_standard_mode(args):
    """
    Run the standard vulnerability scanning mode
    
    Args:
        args: Command line arguments
        
    Returns:
        int: Exit code
    """
    # Validate URL
    if not validate_url(args.url):
        logger.error("Invalid URL provided. Please check the URL format.")
        return 1
    
    # Auto-detect parameter if not provided
    target_param = args.param
    if not target_param:
        target_param = extract_param_from_url(args.url)
        if not target_param:
            logger.error("No parameter found in URL and none specified with --param.")
            return 1
        logger.info(f"Auto-detected parameter: {target_param}")
    
    # Initialize the engine
    engine = XploitEngine(
        url=args.url,
        param=target_param,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        user_agent=args.user_agent,
        cookies=args.cookies,
        headers=args.headers,
        proxy=args.proxy,
        auth=args.auth,
        output_file=args.output,
        output_format=args.format,
        idor_range=args.idor_range
    )
    
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
    
    return 0

def run_realtime_mode(args):
    """
    Run the real-time data retrieval mode
    
    Args:
        args: Command line arguments
        
    Returns:
        int: Exit code
    """
    # Import the real-time modules
    from xploit.utils.realtime_config import RealtimeConfig
    from xploit.modules.realtime_data import RealtimeDataRetriever
    
    # Global variables for real-time mode
    global data_buffer, data_buffer_max_size, start_time, active_sources, layout, live_display
    
    # Initialize variables
    data_buffer = []
    data_buffer_max_size = args.buffer_size if hasattr(args, 'buffer_size') else 100
    active_sources = set()
    layout = None
    live_display = None
    
    # Set up the rich live display
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    
    def create_layout():
        """Create the layout for the live display"""
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
    
    def update_display():
        """Update the live display with the latest data"""
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
        if hasattr(args, 'duration') and args.duration > 0:
            elapsed = time.time() - start_time
            remaining = max(0, args.duration - elapsed)
            footer_text.append(f" | Time remaining: {int(remaining)}s")
        
        layout["footer"].update(Panel(footer_text, border_style="blue"))
    
    def data_callback(data):
        """Callback function for real-time data updates"""
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
    
    def write_to_output(data):
        """Write data to the output file"""
        try:
            if args.format == "json":
                with open(args.output, "a") as f:
                    f.write(json.dumps(data) + "\n")
            elif args.format == "csv":
                import csv
                
                # Flatten the data
                flat_data = {}
                for k, v in data.items():
                    if isinstance(v, dict):
                        for k2, v2 in v.items():
                            flat_data[f"{k}_{k2}"] = v2
                    else:
                        flat_data[k] = v
                
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
    
    try:
        # Load the configuration
        config = RealtimeConfig(args.config)
        config_data = config.load()
        
        if not config_data:
            logger.error(f"Failed to load configuration from {args.config}")
            return 1
        
        # Create the real-time data retriever
        retriever = RealtimeDataRetriever(config=config_data, callback=data_callback)
        
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
                        import json
                        params = json.loads(args.api_params)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid API parameters JSON: {args.api_params}")
                        return 1
                
                if args.api_data:
                    try:
                        import json
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
            if hasattr(args, 'duration') and args.duration > 0:
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
        logger.error(f"Error in real-time mode: {str(e)}")
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1