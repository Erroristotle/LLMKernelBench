"""Database utilities for the VulnLLMEval project."""

import sqlite3
import pandas as pd
import time
import fcntl
import os
from pathlib import Path
import logging
from typing import List, Dict, Any, Optional, Union

logger = logging.getLogger(__name__)

class Database:
    """Database utility class for managing SQLite database operations with file locking."""
    
    def __init__(self, db_path: Union[str, Path]):
        """Initialize database connection.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = Path(db_path)
        self.conn = None
        self.cursor = None
        self.lock_file = None
        self.lock_fd = None
        
    def _acquire_lock(self) -> None:
        """Acquire file lock for database access."""
        lock_path = self.db_path.with_suffix('.lock')
        try:
            self.lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            logger.debug(f"Acquired lock for database: {self.db_path}")
        except (OSError, IOError) as e:
            if self.lock_fd:
                os.close(self.lock_fd)
                self.lock_fd = None
            raise Exception(f"Could not acquire database lock: {e}")
    
    def _release_lock(self) -> None:
        """Release file lock for database access."""
        if self.lock_fd:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                os.close(self.lock_fd)
                self.lock_fd = None
                logger.debug(f"Released lock for database: {self.db_path}")
            except Exception as e:
                logger.warning(f"Error releasing lock: {e}")
        
    def connect(self) -> None:
        """Establish connection to the database with simple approach."""
        # Simple connection without file locking complications
        self.conn = sqlite3.connect(str(self.db_path), timeout=60.0, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Only set essential optimizations to avoid lock issues
        try:
            self.cursor.execute("PRAGMA busy_timeout=60000")  # 60 second timeout
            self.cursor.execute("PRAGMA temp_store=memory")
            self.conn.commit()
        except Exception as e:
            logger.warning(f"Could not set database optimizations: {e}")
        
        logger.debug(f"Connected to database: {self.db_path}")
        
    def disconnect(self) -> None:
        """Close the database connection."""
        if self.conn:
            try:
                self.conn.close()
            except Exception as e:
                logger.warning(f"Error closing database connection: {e}")
            self.conn = None
            self.cursor = None
            
        logger.debug(f"Disconnected from database: {self.db_path}")
    
    def execute(self, query: str, params: tuple = None) -> Any:
        """Execute a query and return the result with retry logic.
        
        Args:
            query: SQL query string
            params: Query parameters (optional)
            
        Returns:
            Query result
        """
        if not self.conn:
            self.connect()
        
        max_retries = 5
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                if params:
                    result = self.cursor.execute(query, params)
                else:
                    result = self.cursor.execute(query)
                return result
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    logger.warning(f"Database locked (attempt {attempt + 1}/{max_retries}), retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    
                    # Try to reconnect
                    try:
                        self.disconnect()
                        self.connect()
                    except:
                        pass
                else:
                    logger.error(f"Database error: {e}")
                    raise
            except Exception as e:
                logger.error(f"Database error: {e}")
                raise
    
    def commit(self) -> None:
        """Commit current transaction."""
        if self.conn:
            self.conn.commit()
    
    def fetch_all(self, query: str, params: tuple = None) -> List[tuple]:
        """Execute a query and fetch all results.
        
        Args:
            query: SQL query string
            params: Query parameters (optional)
            
        Returns:
            List of query result rows
        """
        self.execute(query, params)
        return self.cursor.fetchall()
    
    def fetch_one(self, query: str, params: tuple = None) -> tuple:
        """Execute a query and fetch one result.
        
        Args:
            query: SQL query string
            params: Query parameters (optional)
            
        Returns:
            Single query result row
        """
        self.execute(query, params)
        return self.cursor.fetchone()
    
    def create_table(self, table_name: str, columns: List[str]) -> None:
        """Create a table if it doesn't exist.
        
        Args:
            table_name: Name of the table to create
            columns: List of column definitions
        """
        columns_str = ', '.join(columns)
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns_str})"
        self.execute(query)
        self.commit()
        logger.debug(f"Created table: {table_name}")
    
    def add_column(self, table_name: str, column_def: str) -> bool:
        """Add a column to a table if it doesn't exist.
        
        Args:
            table_name: Name of the table
            column_def: Column definition (name and type)
            
        Returns:
            True if column was added, False if it already existed
        """
        try:
            query = f"ALTER TABLE {table_name} ADD COLUMN {column_def}"
            self.execute(query)
            self.commit()
            logger.debug(f"Added column {column_def} to table {table_name}")
            return True
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug(f"Column {column_def} already exists in table {table_name}")
                return False
            else:
                logger.error(f"Error adding column {column_def} to table {table_name}: {e}")
                raise
    
    def table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database.
        
        Args:
            table_name: Name of the table to check
            
        Returns:
            True if the table exists, False otherwise
        """
        query = f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'"
        result = self.fetch_one(query)
        return result is not None
    
    def column_exists(self, table_name: str, column_name: str) -> bool:
        """Check if a column exists in a table.
        
        Args:
            table_name: Name of the table
            column_name: Name of the column to check
            
        Returns:
            True if the column exists, False otherwise
        """
        query = f"PRAGMA table_info({table_name})"
        columns = self.fetch_all(query)
        return any(column[1] == column_name for column in columns)
    
    def get_columns(self, table_name: str) -> List[str]:
        """Get all column names for a table.
        
        Args:
            table_name: Name of the table
            
        Returns:
            List of column names
        """
        query = f"PRAGMA table_info({table_name})"
        columns = self.fetch_all(query)
        return [column[1] for column in columns]
    
    def insert_dataframe(self, df: pd.DataFrame, table_name: str, if_exists: str = 'append') -> None:
        """Insert a pandas DataFrame into the database.
        
        Args:
            df: DataFrame to insert
            table_name: Target table name
            if_exists: How to behave if the table exists ('fail', 'replace', or 'append')
        """
        if not self.conn:
            self.connect()
            
        df.to_sql(table_name, self.conn, if_exists=if_exists, index=False)
        logger.debug(f"Inserted {len(df)} rows into table {table_name}")
    
    def query_to_dataframe(self, query: str, params: tuple = None) -> pd.DataFrame:
        """Execute a query and return the results as a pandas DataFrame.
        
        Args:
            query: SQL query string
            params: Query parameters (optional)
            
        Returns:
            DataFrame with query results
        """
        if not self.conn:
            self.connect()
            
        if params:
            return pd.read_sql_query(query, self.conn, params=params)
        else:
            return pd.read_sql_query(query, self.conn)
        
    def add_missing_columns(self):
        """Add any missing columns to the vulnerabilities table."""
        try:
            # Ensure connection exists
            if not hasattr(self, 'conn') or self.conn is None:
                self.connect()
                
            # Check if LLM_Ranked_CWE column exists
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA table_info(vulnerabilities)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'LLM_Ranked_CWE' not in columns:
                logger.info("Adding missing LLM_Ranked_CWE column")
                self.execute("ALTER TABLE vulnerabilities ADD COLUMN LLM_Ranked_CWE TEXT")
                self.commit()
                logger.info("LLM_Ranked_CWE column added successfully")
            
        except Exception as e:
            logger.error(f"Error adding missing columns: {e}")

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()