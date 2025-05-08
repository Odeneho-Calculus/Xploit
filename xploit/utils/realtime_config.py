"""
xploit/utils/realtime_config.py - Configuration utilities for real-time data sources
"""

import os
import json
import logging
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger("xploit.utils.realtime_config")

# Get the project's base directory
BASE_DIR = Path(__file__).parent.parent.parent.absolute()
CONFIG_DIR = BASE_DIR / "config"

# Ensure the config directory exists
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

class RealtimeConfig:
    """Configuration manager for real-time data sources"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the configuration manager
        
        Args:
            config_file: Path to the configuration file (default: config/realtime.yaml)
        """
        if config_file:
            self.config_file = Path(config_file)
        else:
            self.config_file = CONFIG_DIR / "realtime.yaml"
        
        # Default configuration
        self.config = {
            "apis": [],
            "websockets": [],
            "databases": [],
            "logs": []
        }
        
        # Load the configuration if it exists
        self.load()
    
    def load(self) -> Dict[str, Any]:
        """
        Load the configuration from file
        
        Returns:
            Dict containing the configuration
        """
        if not self.config_file.exists():
            logger.warning(f"Configuration file not found: {self.config_file}")
            return self.config
        
        try:
            with open(self.config_file, "r") as f:
                if self.config_file.suffix.lower() == ".json":
                    self.config = json.load(f)
                elif self.config_file.suffix.lower() in [".yaml", ".yml"]:
                    self.config = yaml.safe_load(f)
                else:
                    logger.error(f"Unsupported configuration file format: {self.config_file.suffix}")
            
            logger.info(f"Loaded configuration from {self.config_file}")
            return self.config
        
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            return self.config
    
    def save(self) -> bool:
        """
        Save the configuration to file
        
        Returns:
            bool: True if saved successfully, False otherwise
        """
        try:
            # Create the directory if it doesn't exist
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, "w") as f:
                if self.config_file.suffix.lower() == ".json":
                    json.dump(self.config, f, indent=2)
                elif self.config_file.suffix.lower() in [".yaml", ".yml"]:
                    yaml.dump(self.config, f, default_flow_style=False)
                else:
                    logger.error(f"Unsupported configuration file format: {self.config_file.suffix}")
                    return False
            
            logger.info(f"Saved configuration to {self.config_file}")
            return True
        
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            return False
    
    def add_api(self, api_config: Dict[str, Any]) -> bool:
        """
        Add an API configuration
        
        Args:
            api_config: API configuration
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        if "name" not in api_config or "url" not in api_config:
            logger.error("API configuration must include 'name' and 'url'")
            return False
        
        # Check if an API with the same name already exists
        for i, api in enumerate(self.config["apis"]):
            if api.get("name") == api_config["name"]:
                # Update the existing API
                self.config["apis"][i] = api_config
                logger.info(f"Updated API configuration: {api_config['name']}")
                return self.save()
        
        # Add the new API
        self.config["apis"].append(api_config)
        logger.info(f"Added API configuration: {api_config['name']}")
        return self.save()
    
    def remove_api(self, api_name: str) -> bool:
        """
        Remove an API configuration
        
        Args:
            api_name: Name of the API to remove
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        for i, api in enumerate(self.config["apis"]):
            if api.get("name") == api_name:
                del self.config["apis"][i]
                logger.info(f"Removed API configuration: {api_name}")
                return self.save()
        
        logger.warning(f"API configuration not found: {api_name}")
        return False
    
    def add_websocket(self, ws_config: Dict[str, Any]) -> bool:
        """
        Add a WebSocket configuration
        
        Args:
            ws_config: WebSocket configuration
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        if "name" not in ws_config or "url" not in ws_config:
            logger.error("WebSocket configuration must include 'name' and 'url'")
            return False
        
        # Check if a WebSocket with the same name already exists
        for i, ws in enumerate(self.config["websockets"]):
            if ws.get("name") == ws_config["name"]:
                # Update the existing WebSocket
                self.config["websockets"][i] = ws_config
                logger.info(f"Updated WebSocket configuration: {ws_config['name']}")
                return self.save()
        
        # Add the new WebSocket
        self.config["websockets"].append(ws_config)
        logger.info(f"Added WebSocket configuration: {ws_config['name']}")
        return self.save()
    
    def remove_websocket(self, ws_name: str) -> bool:
        """
        Remove a WebSocket configuration
        
        Args:
            ws_name: Name of the WebSocket to remove
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        for i, ws in enumerate(self.config["websockets"]):
            if ws.get("name") == ws_name:
                del self.config["websockets"][i]
                logger.info(f"Removed WebSocket configuration: {ws_name}")
                return self.save()
        
        logger.warning(f"WebSocket configuration not found: {ws_name}")
        return False
    
    def add_database(self, db_config: Dict[str, Any]) -> bool:
        """
        Add a database configuration
        
        Args:
            db_config: Database configuration
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        if "name" not in db_config or "type" not in db_config:
            logger.error("Database configuration must include 'name' and 'type'")
            return False
        
        # Check if a database with the same name already exists
        for i, db in enumerate(self.config["databases"]):
            if db.get("name") == db_config["name"]:
                # Update the existing database
                self.config["databases"][i] = db_config
                logger.info(f"Updated database configuration: {db_config['name']}")
                return self.save()
        
        # Add the new database
        self.config["databases"].append(db_config)
        logger.info(f"Added database configuration: {db_config['name']}")
        return self.save()
    
    def remove_database(self, db_name: str) -> bool:
        """
        Remove a database configuration
        
        Args:
            db_name: Name of the database to remove
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        for i, db in enumerate(self.config["databases"]):
            if db.get("name") == db_name:
                del self.config["databases"][i]
                logger.info(f"Removed database configuration: {db_name}")
                return self.save()
        
        logger.warning(f"Database configuration not found: {db_name}")
        return False
    
    def add_log(self, log_config: Dict[str, Any]) -> bool:
        """
        Add a log configuration
        
        Args:
            log_config: Log configuration
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        if "name" not in log_config or "path" not in log_config:
            logger.error("Log configuration must include 'name' and 'path'")
            return False
        
        # Check if a log with the same name already exists
        for i, log in enumerate(self.config["logs"]):
            if log.get("name") == log_config["name"]:
                # Update the existing log
                self.config["logs"][i] = log_config
                logger.info(f"Updated log configuration: {log_config['name']}")
                return self.save()
        
        # Add the new log
        self.config["logs"].append(log_config)
        logger.info(f"Added log configuration: {log_config['name']}")
        return self.save()
    
    def remove_log(self, log_name: str) -> bool:
        """
        Remove a log configuration
        
        Args:
            log_name: Name of the log to remove
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        for i, log in enumerate(self.config["logs"]):
            if log.get("name") == log_name:
                del self.config["logs"][i]
                logger.info(f"Removed log configuration: {log_name}")
                return self.save()
        
        logger.warning(f"Log configuration not found: {log_name}")
        return False
    
    def get_api(self, api_name: str) -> Optional[Dict[str, Any]]:
        """
        Get an API configuration
        
        Args:
            api_name: Name of the API
            
        Returns:
            Dict containing the API configuration or None if not found
        """
        for api in self.config["apis"]:
            if api.get("name") == api_name:
                return api
        
        return None
    
    def get_websocket(self, ws_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a WebSocket configuration
        
        Args:
            ws_name: Name of the WebSocket
            
        Returns:
            Dict containing the WebSocket configuration or None if not found
        """
        for ws in self.config["websockets"]:
            if ws.get("name") == ws_name:
                return ws
        
        return None
    
    def get_database(self, db_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a database configuration
        
        Args:
            db_name: Name of the database
            
        Returns:
            Dict containing the database configuration or None if not found
        """
        for db in self.config["databases"]:
            if db.get("name") == db_name:
                return db
        
        return None
    
    def get_log(self, log_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a log configuration
        
        Args:
            log_name: Name of the log
            
        Returns:
            Dict containing the log configuration or None if not found
        """
        for log in self.config["logs"]:
            if log.get("name") == log_name:
                return log
        
        return None
    
    def get_all_apis(self) -> List[Dict[str, Any]]:
        """
        Get all API configurations
        
        Returns:
            List of API configurations
        """
        return self.config["apis"]
    
    def get_all_websockets(self) -> List[Dict[str, Any]]:
        """
        Get all WebSocket configurations
        
        Returns:
            List of WebSocket configurations
        """
        return self.config["websockets"]
    
    def get_all_databases(self) -> List[Dict[str, Any]]:
        """
        Get all database configurations
        
        Returns:
            List of database configurations
        """
        return self.config["databases"]
    
    def get_all_logs(self) -> List[Dict[str, Any]]:
        """
        Get all log configurations
        
        Returns:
            List of log configurations
        """
        return self.config["logs"]