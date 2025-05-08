"""
xploit/modules/realtime_data.py - Real-time data retrieval module for the XPLOIT tool
"""

import json
import time
import logging
import asyncio
import threading
from typing import Dict, List, Any, Optional, Union, Callable
from urllib.parse import urlparse

import aiohttp
import websockets
import requests
from requests.exceptions import RequestException

# Database connectors
try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

try:
    import pyodbc
    MSSQL_AVAILABLE = True
except ImportError:
    MSSQL_AVAILABLE = False

try:
    import oracledb
    ORACLE_AVAILABLE = True
except ImportError:
    ORACLE_AVAILABLE = False

logger = logging.getLogger("xploit.modules.realtime_data")

class RealtimeDataRetriever:
    """Real-time data retrieval module for accessing live data sources"""
    
    def __init__(
        self,
        config: Dict[str, Any] = None,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        """
        Initialize the RealtimeDataRetriever module
        
        Args:
            config: Configuration for data sources
            callback: Callback function for real-time data updates
        """
        self.config = config or {}
        self.callback = callback
        self.running = False
        self.threads = []
        self.websocket_connections = {}
        self.db_connections = {}
        self.api_sessions = {}
        
        # Set up event loop for async operations
        self.loop = asyncio.new_event_loop()
        
    def start(self) -> bool:
        """
        Start real-time data retrieval
        
        Returns:
            bool: True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("Real-time data retrieval is already running")
            return False
            
        self.running = True
        
        # Start API polling if configured
        api_configs = self.config.get("apis", [])
        if api_configs:
            for api_config in api_configs:
                self._start_api_polling(api_config)
        
        # Start WebSocket connections if configured
        websocket_configs = self.config.get("websockets", [])
        if websocket_configs:
            for ws_config in websocket_configs:
                self._start_websocket_connection(ws_config)
        
        # Start database monitoring if configured
        db_configs = self.config.get("databases", [])
        if db_configs:
            for db_config in db_configs:
                self._start_database_monitoring(db_config)
        
        # Start log monitoring if configured
        log_configs = self.config.get("logs", [])
        if log_configs:
            for log_config in log_configs:
                self._start_log_monitoring(log_config)
        
        logger.info("Real-time data retrieval started")
        return True
    
    def stop(self) -> bool:
        """
        Stop real-time data retrieval
        
        Returns:
            bool: True if stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("Real-time data retrieval is not running")
            return False
            
        self.running = False
        
        # Stop all threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
        
        # Close WebSocket connections
        for ws_name, ws_conn in self.websocket_connections.items():
            try:
                if not self.loop.is_closed():
                    self.loop.run_until_complete(ws_conn.close())
                logger.debug(f"Closed WebSocket connection: {ws_name}")
            except Exception as e:
                logger.error(f"Error closing WebSocket connection {ws_name}: {str(e)}")
        
        # Close database connections
        for db_name, db_conn in self.db_connections.items():
            try:
                db_conn.close()
                logger.debug(f"Closed database connection: {db_name}")
            except Exception as e:
                logger.error(f"Error closing database connection {db_name}: {str(e)}")
        
        # Close API sessions
        for api_name, session in self.api_sessions.items():
            try:
                session.close()
                logger.debug(f"Closed API session: {api_name}")
            except Exception as e:
                logger.error(f"Error closing API session {api_name}: {str(e)}")
        
        # Clear all collections
        self.threads.clear()
        self.websocket_connections.clear()
        self.db_connections.clear()
        self.api_sessions.clear()
        
        # Close the event loop
        if not self.loop.is_closed():
            self.loop.close()
        
        logger.info("Real-time data retrieval stopped")
        return True
    
    def _start_api_polling(self, api_config: Dict[str, Any]) -> None:
        """
        Start polling an API endpoint
        
        Args:
            api_config: API configuration
        """
        api_name = api_config.get("name", "unnamed_api")
        api_url = api_config.get("url")
        method = api_config.get("method", "GET").upper()
        headers = api_config.get("headers", {})
        params = api_config.get("params", {})
        data = api_config.get("data", {})
        auth = api_config.get("auth", None)
        interval = api_config.get("interval", 60)  # Default: 60 seconds
        
        if not api_url:
            logger.error(f"Missing URL for API {api_name}")
            return
        
        # Create a session for this API
        session = requests.Session()
        if headers:
            session.headers.update(headers)
        
        # Store the session
        self.api_sessions[api_name] = session
        
        # Create and start the polling thread
        thread = threading.Thread(
            target=self._api_polling_worker,
            args=(api_name, api_url, method, params, data, auth, interval),
            daemon=True
        )
        thread.start()
        self.threads.append(thread)
        logger.info(f"Started API polling for {api_name} at {api_url} (interval: {interval}s)")
    
    def _api_polling_worker(
        self,
        api_name: str,
        url: str,
        method: str,
        params: Dict[str, Any],
        data: Dict[str, Any],
        auth: Optional[tuple],
        interval: int
    ) -> None:
        """
        Worker function for API polling
        
        Args:
            api_name: Name of the API
            url: API URL
            method: HTTP method
            params: Query parameters
            data: Request data
            auth: Authentication tuple (username, password)
            interval: Polling interval in seconds
        """
        session = self.api_sessions.get(api_name)
        if not session:
            logger.error(f"No session found for API {api_name}")
            return
        
        while self.running:
            try:
                # Make the request
                response = session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=data if method in ["POST", "PUT", "PATCH"] else None,
                    auth=auth,
                    timeout=10
                )
                
                # Process the response
                if response.status_code == 200:
                    try:
                        response_data = response.json()
                        
                        # Call the callback with the data
                        if self.callback:
                            self.callback({
                                "source": "api",
                                "name": api_name,
                                "timestamp": time.time(),
                                "data": response_data
                            })
                        
                        logger.debug(f"Received data from API {api_name}")
                    except ValueError:
                        logger.warning(f"API {api_name} returned non-JSON response")
                else:
                    logger.warning(f"API {api_name} returned status code {response.status_code}")
            
            except RequestException as e:
                logger.error(f"Error polling API {api_name}: {str(e)}")
            
            # Sleep for the specified interval
            time.sleep(interval)
    
    def _start_websocket_connection(self, ws_config: Dict[str, Any]) -> None:
        """
        Start a WebSocket connection
        
        Args:
            ws_config: WebSocket configuration
        """
        ws_name = ws_config.get("name", "unnamed_websocket")
        ws_url = ws_config.get("url")
        headers = ws_config.get("headers", {})
        auth = ws_config.get("auth", None)
        
        if not ws_url:
            logger.error(f"Missing URL for WebSocket {ws_name}")
            return
        
        # Create and start the WebSocket thread
        thread = threading.Thread(
            target=self._websocket_worker,
            args=(ws_name, ws_url, headers, auth),
            daemon=True
        )
        thread.start()
        self.threads.append(thread)
        logger.info(f"Started WebSocket connection for {ws_name} at {ws_url}")
    
    def _websocket_worker(
        self,
        ws_name: str,
        url: str,
        headers: Dict[str, str],
        auth: Optional[Dict[str, str]]
    ) -> None:
        """
        Worker function for WebSocket connections
        
        Args:
            ws_name: Name of the WebSocket
            url: WebSocket URL
            headers: HTTP headers
            auth: Authentication data
        """
        async def _connect_and_listen():
            try:
                # Connect to the WebSocket
                async with websockets.connect(url, extra_headers=headers) as websocket:
                    # Store the connection
                    self.websocket_connections[ws_name] = websocket
                    
                    # Send authentication if required
                    if auth:
                        await websocket.send(json.dumps(auth))
                    
                    # Listen for messages
                    while self.running:
                        try:
                            message = await websocket.recv()
                            
                            # Parse the message
                            try:
                                data = json.loads(message)
                                
                                # Call the callback with the data
                                if self.callback:
                                    self.callback({
                                        "source": "websocket",
                                        "name": ws_name,
                                        "timestamp": time.time(),
                                        "data": data
                                    })
                                
                                logger.debug(f"Received data from WebSocket {ws_name}")
                            except ValueError:
                                logger.warning(f"WebSocket {ws_name} received non-JSON message")
                        
                        except websockets.exceptions.ConnectionClosed:
                            logger.warning(f"WebSocket {ws_name} connection closed")
                            break
            
            except Exception as e:
                logger.error(f"Error in WebSocket {ws_name}: {str(e)}")
                
                # Try to reconnect after a delay
                if self.running:
                    await asyncio.sleep(5)
                    asyncio.create_task(_connect_and_listen())
        
        # Set up the event loop in this thread
        asyncio.set_event_loop(self.loop)
        
        # Start the WebSocket connection
        self.loop.run_until_complete(_connect_and_listen())
    
    def _start_database_monitoring(self, db_config: Dict[str, Any]) -> None:
        """
        Start monitoring a database
        
        Args:
            db_config: Database configuration
        """
        db_name = db_config.get("name", "unnamed_db")
        db_type = db_config.get("type", "").lower()
        query = db_config.get("query")
        interval = db_config.get("interval", 60)  # Default: 60 seconds
        
        if not db_type:
            logger.error(f"Missing database type for {db_name}")
            return
        
        if not query:
            logger.error(f"Missing query for database {db_name}")
            return
        
        # Check if the required database driver is available
        if db_type == "mysql" and not MYSQL_AVAILABLE:
            logger.error(f"MySQL driver (pymysql) not available for database {db_name}")
            return
        elif db_type == "postgres" and not POSTGRES_AVAILABLE:
            logger.error(f"PostgreSQL driver (psycopg2) not available for database {db_name}")
            return
        elif db_type == "mssql" and not MSSQL_AVAILABLE:
            logger.error(f"MSSQL driver (pyodbc) not available for database {db_name}")
            return
        elif db_type == "oracle" and not ORACLE_AVAILABLE:
            logger.error(f"Oracle driver (oracledb) not available for database {db_name}")
            return
        
        # Connect to the database
        try:
            conn = self._connect_to_database(db_config)
            if not conn:
                logger.error(f"Failed to connect to database {db_name}")
                return
            
            # Store the connection
            self.db_connections[db_name] = conn
            
            # Create and start the monitoring thread
            thread = threading.Thread(
                target=self._database_monitoring_worker,
                args=(db_name, db_type, query, interval),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            logger.info(f"Started monitoring for database {db_name} (interval: {interval}s)")
        
        except Exception as e:
            logger.error(f"Error setting up database monitoring for {db_name}: {str(e)}")
    
    def _connect_to_database(self, db_config: Dict[str, Any]) -> Any:
        """
        Connect to a database
        
        Args:
            db_config: Database configuration
            
        Returns:
            Database connection object or None if connection failed
        """
        db_type = db_config.get("type", "").lower()
        host = db_config.get("host", "localhost")
        port = db_config.get("port")
        database = db_config.get("database")
        username = db_config.get("username")
        password = db_config.get("password")
        
        try:
            if db_type == "mysql":
                if not MYSQL_AVAILABLE:
                    return None
                
                conn = pymysql.connect(
                    host=host,
                    port=port or 3306,
                    user=username,
                    password=password,
                    database=database
                )
                return conn
            
            elif db_type == "postgres":
                if not POSTGRES_AVAILABLE:
                    return None
                
                conn = psycopg2.connect(
                    host=host,
                    port=port or 5432,
                    user=username,
                    password=password,
                    dbname=database
                )
                return conn
            
            elif db_type == "mssql":
                if not MSSQL_AVAILABLE:
                    return None
                
                conn_str = (
                    f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                    f"SERVER={host},{port or 1433};"
                    f"DATABASE={database};"
                    f"UID={username};"
                    f"PWD={password}"
                )
                conn = pyodbc.connect(conn_str)
                return conn
            
            elif db_type == "oracle":
                if not ORACLE_AVAILABLE:
                    return None
                
                conn = oracledb.connect(
                    user=username,
                    password=password,
                    dsn=f"{host}:{port or 1521}/{database}"
                )
                return conn
            
            elif db_type == "sqlite":
                import sqlite3
                conn = sqlite3.connect(database)
                return conn
            
            else:
                logger.error(f"Unsupported database type: {db_type}")
                return None
        
        except Exception as e:
            logger.error(f"Error connecting to {db_type} database: {str(e)}")
            return None
    
    def _database_monitoring_worker(
        self,
        db_name: str,
        db_type: str,
        query: str,
        interval: int
    ) -> None:
        """
        Worker function for database monitoring
        
        Args:
            db_name: Name of the database
            db_type: Type of the database
            query: SQL query to execute
            interval: Polling interval in seconds
        """
        conn = self.db_connections.get(db_name)
        if not conn:
            logger.error(f"No connection found for database {db_name}")
            return
        
        last_data_hash = None
        
        while self.running:
            try:
                # Execute the query
                cursor = conn.cursor()
                cursor.execute(query)
                
                # Fetch the results
                columns = [col[0] for col in cursor.description]
                results = []
                
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
                
                # Close the cursor
                cursor.close()
                
                # Generate a hash of the results to detect changes
                results_str = json.dumps(results, sort_keys=True)
                current_hash = hash(results_str)
                
                # Check if the data has changed
                if current_hash != last_data_hash:
                    # Call the callback with the data
                    if self.callback:
                        self.callback({
                            "source": "database",
                            "name": db_name,
                            "timestamp": time.time(),
                            "data": results
                        })
                    
                    logger.debug(f"Received new data from database {db_name}")
                    last_data_hash = current_hash
            
            except Exception as e:
                logger.error(f"Error querying database {db_name}: {str(e)}")
                
                # Try to reconnect if the connection was lost
                try:
                    conn.ping(reconnect=True)
                except:
                    logger.warning(f"Reconnecting to database {db_name}")
                    conn = self._connect_to_database(self.config.get("databases", [])[db_name])
                    if conn:
                        self.db_connections[db_name] = conn
            
            # Sleep for the specified interval
            time.sleep(interval)
    
    def _start_log_monitoring(self, log_config: Dict[str, Any]) -> None:
        """
        Start monitoring a log file
        
        Args:
            log_config: Log configuration
        """
        log_name = log_config.get("name", "unnamed_log")
        log_path = log_config.get("path")
        patterns = log_config.get("patterns", [])
        
        if not log_path:
            logger.error(f"Missing path for log {log_name}")
            return
        
        # Create and start the log monitoring thread
        thread = threading.Thread(
            target=self._log_monitoring_worker,
            args=(log_name, log_path, patterns),
            daemon=True
        )
        thread.start()
        self.threads.append(thread)
        logger.info(f"Started monitoring log file {log_name} at {log_path}")
    
    def _log_monitoring_worker(
        self,
        log_name: str,
        log_path: str,
        patterns: List[str]
    ) -> None:
        """
        Worker function for log monitoring
        
        Args:
            log_name: Name of the log
            log_path: Path to the log file
            patterns: Regex patterns to match
        """
        import re
        import os
        
        # Compile the regex patterns
        compiled_patterns = [re.compile(pattern) for pattern in patterns]
        
        # Get the initial file size
        try:
            file_size = os.path.getsize(log_path)
        except OSError:
            logger.error(f"Log file {log_path} not found")
            return
        
        while self.running:
            try:
                # Check if the file has grown
                current_size = os.path.getsize(log_path)
                
                if current_size > file_size:
                    # Open the file and seek to the previous position
                    with open(log_path, "r") as f:
                        f.seek(file_size)
                        
                        # Read the new lines
                        new_lines = f.read()
                        
                        # Update the file size
                        file_size = current_size
                        
                        # Process the new lines
                        for line in new_lines.splitlines():
                            # Check if the line matches any of the patterns
                            for i, pattern in enumerate(compiled_patterns):
                                match = pattern.search(line)
                                if match:
                                    # Call the callback with the matched data
                                    if self.callback:
                                        self.callback({
                                            "source": "log",
                                            "name": log_name,
                                            "timestamp": time.time(),
                                            "pattern_index": i,
                                            "pattern": patterns[i],
                                            "line": line,
                                            "match": match.groupdict() if match.groupdict() else match.groups()
                                        })
                                    
                                    logger.debug(f"Matched pattern in log {log_name}: {line[:50]}...")
            
            except Exception as e:
                logger.error(f"Error monitoring log {log_name}: {str(e)}")
            
            # Sleep for a short interval
            time.sleep(1)

    def query_api(self, api_name: str, endpoint: str = None, method: str = "GET", 
                 params: Dict[str, Any] = None, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Query an API endpoint directly (one-time request)
        
        Args:
            api_name: Name of the API configuration to use
            endpoint: Optional endpoint to append to the base URL
            method: HTTP method
            params: Query parameters
            data: Request data
            
        Returns:
            Dict containing the API response
        """
        # Find the API configuration
        api_config = None
        for cfg in self.config.get("apis", []):
            if cfg.get("name") == api_name:
                api_config = cfg
                break
        
        if not api_config:
            logger.error(f"API configuration not found: {api_name}")
            return {"error": f"API configuration not found: {api_name}"}
        
        # Get the base URL
        base_url = api_config.get("url")
        if not base_url:
            logger.error(f"Missing URL for API {api_name}")
            return {"error": f"Missing URL for API {api_name}"}
        
        # Construct the full URL
        url = base_url
        if endpoint:
            url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Get the session or create a new one
        session = self.api_sessions.get(api_name)
        if not session:
            session = requests.Session()
            headers = api_config.get("headers", {})
            if headers:
                session.headers.update(headers)
        
        # Make the request
        try:
            response = session.request(
                method=method.upper(),
                url=url,
                params=params,
                json=data if method.upper() in ["POST", "PUT", "PATCH"] else None,
                auth=api_config.get("auth"),
                timeout=10
            )
            
            # Process the response
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError:
                    return {"error": f"API {api_name} returned non-JSON response", "text": response.text}
            else:
                return {
                    "error": f"API {api_name} returned status code {response.status_code}",
                    "status_code": response.status_code,
                    "text": response.text
                }
        
        except RequestException as e:
            logger.error(f"Error querying API {api_name}: {str(e)}")
            return {"error": f"Error querying API {api_name}: {str(e)}"}
    
    def query_database(self, db_name: str, query: str, params: tuple = None) -> List[Dict[str, Any]]:
        """
        Query a database directly (one-time query)
        
        Args:
            db_name: Name of the database configuration to use
            query: SQL query to execute
            params: Query parameters
            
        Returns:
            List of dictionaries containing the query results
        """
        # Find the database connection
        conn = self.db_connections.get(db_name)
        if not conn:
            logger.error(f"Database connection not found: {db_name}")
            return [{"error": f"Database connection not found: {db_name}"}]
        
        try:
            # Execute the query
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            # Fetch the results
            columns = [col[0] for col in cursor.description]
            results = []
            
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            # Close the cursor
            cursor.close()
            
            return results
        
        except Exception as e:
            logger.error(f"Error querying database {db_name}: {str(e)}")
            return [{"error": f"Error querying database {db_name}: {str(e)}"}]