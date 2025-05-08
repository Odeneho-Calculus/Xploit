"""
xploit/utils/database.py - Database utility for storing and retrieving scan results
"""

import os
import json
import sqlite3
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple

# Get the project's base directory
BASE_DIR = Path(__file__).parent.parent.parent.absolute()
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = DATA_DIR / "output"

# Ensure the output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("xploit.utils.database")

class Database:
    """Database utility for storing and retrieving scan results"""
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the database connection
        
        Args:
            db_path: Path to the SQLite database file (default: data/output/results.db)
        """
        if db_path is None:
            self.db_path = OUTPUT_DIR / "results.db"
        else:
            self.db_path = Path(db_path)
        
        # Create directory if it doesn't exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize connection
        self.conn = None
        self.cursor = None
        
        # Connect to the database
        self._connect()
        
        # Initialize database schema
        self._initialize_schema()
    
    def _connect(self):
        """Connect to the SQLite database"""
        try:
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.row_factory = sqlite3.Row  # Enable row factory for dict-like rows
            self.cursor = self.conn.cursor()
            logger.debug(f"Connected to database at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            raise
    
    def _initialize_schema(self):
        """Initialize database schema"""
        try:
            # Create scans table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                target_param TEXT NOT NULL,
                start_time REAL NOT NULL,
                end_time REAL,
                duration REAL,
                requests_made INTEGER DEFAULT 0,
                unique_responses INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running',
                error TEXT
            )
            ''')
            
            # Create vulnerabilities table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                param_value TEXT,
                description TEXT,
                evidence TEXT,
                confidence REAL DEFAULT 0.0,
                severity TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
            ''')
            
            # Create data_points table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_points (
                data_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                param_value TEXT,
                data_type TEXT,
                value TEXT,
                confidence REAL DEFAULT 0.0,
                timestamp REAL DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
            ''')
            
            # Create responses table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                response_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                param_value TEXT NOT NULL,
                url TEXT NOT NULL,
                status_code INTEGER,
                content_hash TEXT,
                content_length INTEGER,
                response_time REAL,
                headers TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
            ''')
            
            self.conn.commit()
            logger.debug("Database schema initialized")
        except sqlite3.Error as e:
            logger.error(f"Error initializing database schema: {e}")
            raise
    
    def create_scan(self, target_url: str, target_param: str) -> int:
        """
        Create a new scan record
        
        Args:
            target_url: Target URL
            target_param: Target parameter
            
        Returns:
            scan_id: ID of the created scan
        """
        try:
            # Insert scan record
            self.cursor.execute(
                "INSERT INTO scans (target_url, target_param, start_time, status) VALUES (?, ?, ?, ?)",
                (target_url, target_param, time.time(), "running")
            )
            self.conn.commit()
            
            # Get the inserted scan_id
            scan_id = self.cursor.lastrowid
            logger.debug(f"Created scan #{scan_id} for {target_url}")
            return scan_id
        except sqlite3.Error as e:
            logger.error(f"Error creating scan: {e}")
            self.conn.rollback()
            raise
    
    def update_scan(self, scan_id: int, data: Dict[str, Any]) -> bool:
        """
        Update a scan record
        
        Args:
            scan_id: ID of the scan
            data: Data to update (dict with column names as keys)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Build the SET clause dynamically
            set_clause = ", ".join([f"{key} = ?" for key in data.keys()])
            values = list(data.values())
            values.append(scan_id)
            
            # Execute the update
            self.cursor.execute(
                f"UPDATE scans SET {set_clause} WHERE scan_id = ?",
                values
            )
            self.conn.commit()
            logger.debug(f"Updated scan #{scan_id}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating scan #{scan_id}: {e}")
            self.conn.rollback()
            return False
    
    def complete_scan(self, scan_id: int, status: str = "completed", error: Optional[str] = None) -> bool:
        """
        Mark a scan as completed
        
        Args:
            scan_id: ID of the scan
            status: Status of the scan (completed, failed, cancelled)
            error: Error message if failed
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            end_time = time.time()
            
            # Get the start time
            self.cursor.execute("SELECT start_time FROM scans WHERE scan_id = ?", (scan_id,))
            result = self.cursor.fetchone()
            
            if not result:
                logger.error(f"Scan #{scan_id} not found")
                return False
            
            start_time = result[0]
            duration = end_time - start_time
            
            # Update the scan
            self.cursor.execute(
                "UPDATE scans SET end_time = ?, duration = ?, status = ?, error = ? WHERE scan_id = ?",
                (end_time, duration, status, error, scan_id)
            )
            self.conn.commit()
            logger.debug(f"Completed scan #{scan_id} with status '{status}'")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error completing scan #{scan_id}: {e}")
            self.conn.rollback()
            return False
    
    def add_vulnerability(self, scan_id: int, vuln_data: Dict[str, Any]) -> int:
        """
        Add a vulnerability record
        
        Args:
            scan_id: ID of the scan
            vuln_data: Vulnerability data
            
        Returns:
            vuln_id: ID of the created vulnerability record
        """
        try:
            # Ensure scan_id is included
            vuln_data["scan_id"] = scan_id
            
            # Build the INSERT statement dynamically
            columns = ", ".join(vuln_data.keys())
            placeholders = ", ".join(["?" for _ in vuln_data.keys()])
            
            self.cursor.execute(
                f"INSERT INTO vulnerabilities ({columns}) VALUES ({placeholders})",
                list(vuln_data.values())
            )
            self.conn.commit()
            
            vuln_id = self.cursor.lastrowid
            logger.debug(f"Added vulnerability #{vuln_id} to scan #{scan_id}")
            return vuln_id
        except sqlite3.Error as e:
            logger.error(f"Error adding vulnerability to scan #{scan_id}: {e}")
            self.conn.rollback()
            raise
    
    def add_data_point(self, scan_id: int, data_point: Dict[str, Any]) -> int:
        """
        Add a data point record
        
        Args:
            scan_id: ID of the scan
            data_point: Data point data
            
        Returns:
            data_id: ID of the created data point record
        """
        try:
            # Ensure scan_id is included
            data_point["scan_id"] = scan_id
            
            # Add timestamp if not provided
            if "timestamp" not in data_point:
                data_point["timestamp"] = time.time()
            
            # Build the INSERT statement dynamically
            columns = ", ".join(data_point.keys())
            placeholders = ", ".join(["?" for _ in data_point.keys()])
            
            self.cursor.execute(
                f"INSERT INTO data_points ({columns}) VALUES ({placeholders})",
                list(data_point.values())
            )
            self.conn.commit()
            
            data_id = self.cursor.lastrowid
            logger.debug(f"Added data point #{data_id} to scan #{scan_id}")
            return data_id
        except sqlite3.Error as e:
            logger.error(f"Error adding data point to scan #{scan_id}: {e}")
            self.conn.rollback()
            raise
    
    def add_response(self, scan_id: int, response_data: Dict[str, Any]) -> int:
        """
        Add a response record
        
        Args:
            scan_id: ID of the scan
            response_data: Response data
            
        Returns:
            response_id: ID of the created response record
        """
        try:
            # Ensure scan_id is included
            response_data["scan_id"] = scan_id
            
            # Convert headers to JSON if needed
            if "headers" in response_data and isinstance(response_data["headers"], dict):
                response_data["headers"] = json.dumps(response_data["headers"])
            
            # Build the INSERT statement dynamically
            columns = ", ".join(response_data.keys())
            placeholders = ", ".join(["?" for _ in response_data.keys()])
            
            self.cursor.execute(
                f"INSERT INTO responses ({columns}) VALUES ({placeholders})",
                list(response_data.values())
            )
            self.conn.commit()
            
            response_id = self.cursor.lastrowid
            logger.debug(f"Added response #{response_id} to scan #{scan_id}")
            return response_id
        except sqlite3.Error as e:
            logger.error(f"Error adding response to scan #{scan_id}: {e}")
            self.conn.rollback()
            raise
    
    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a scan record
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Dict containing scan data or None if not found
        """
        try:
            self.cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = self.cursor.fetchone()
            
            if row:
                return dict(row)
            return None
        except sqlite3.Error as e:
            logger.error(f"Error getting scan #{scan_id}: {e}")
            return None
    
    def get_vulnerabilities(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a scan
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            List of vulnerabilities
        """
        try:
            self.cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
            rows = self.cursor.fetchall()
            
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error getting vulnerabilities for scan #{scan_id}: {e}")
            return []
    
    def get_data_points(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Get data points for a scan
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            List of data points
        """
        try:
            self.cursor.execute("SELECT * FROM data_points WHERE scan_id = ?", (scan_id,))
            rows = self.cursor.fetchall()
            
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error getting data points for scan #{scan_id}: {e}")
            return []
    
    def get_responses(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Get responses for a scan
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            List of responses
        """
        try:
            self.cursor.execute("SELECT * FROM responses WHERE scan_id = ?", (scan_id,))
            rows = self.cursor.fetchall()
            
            # Parse JSON headers
            result = []
            for row in rows:
                row_dict = dict(row)
                if "headers" in row_dict and row_dict["headers"]:
                    try:
                        row_dict["headers"] = json.loads(row_dict["headers"])
                    except json.JSONDecodeError:
                        pass
                result.append(row_dict)
            
            return result
        except sqlite3.Error as e:
            logger.error(f"Error getting responses for scan #{scan_id}: {e}")
            return []
    
    def get_full_scan_results(self, scan_id: int) -> Dict[str, Any]:
        """
        Get full scan results including vulnerabilities, data points, and responses
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Dict containing full scan results
        """
        scan = self.get_scan(scan_id)
        
        if not scan:
            logger.error(f"Scan #{scan_id} not found")
            return {}
        
        return {
            "scan": scan,
            "vulnerabilities": self.get_vulnerabilities(scan_id),
            "data_points": self.get_data_points(scan_id),
            "responses": self.get_responses(scan_id)
        }
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent scans
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of recent scans
        """
        try:
            self.cursor.execute("SELECT * FROM scans ORDER BY start_time DESC LIMIT ?", (limit,))
            rows = self.cursor.fetchall()
            
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error getting recent scans: {e}")
            return []
    
    def export_scan_to_json(self, scan_id: int, output_path: Optional[str] = None) -> Optional[str]:
        """
        Export scan results to JSON
        
        Args:
            scan_id: ID of the scan
            output_path: Path to save the JSON file (default: data/output/scan_{scan_id}.json)
            
        Returns:
            Path to the saved JSON file or None if failed
        """
        try:
            results = self.get_full_scan_results(scan_id)
            
            if not results:
                logger.error(f"No results found for scan #{scan_id}")
                return None
            
            if output_path is None:
                output_path = OUTPUT_DIR / f"scan_{scan_id}.json"
            else:
                output_path = Path(output_path)
            
            # Create directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Exported scan #{scan_id} to {output_path}")
            return str(output_path)
        except Exception as e:
            logger.error(f"Error exporting scan #{scan_id} to JSON: {e}")
            return None
    
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()
            logger.debug("Database connection closed")