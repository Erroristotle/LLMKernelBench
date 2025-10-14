"""Vulnerability dataset builder module."""

import os
import pandas as pd
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union

from utils.database import Database
from utils.logger import setup_logger
from dataset.git_interaction import GitInteraction

logger = logging.getLogger(__name__)

class DatasetBuilder:
    """Class for building the vulnerability dataset."""
    
    def __init__(
        self, 
        csv_file_path: Union[str, Path], 
        db_path: Union[str, Path], 
        repo_path: Union[str, Path]
    ):
        """Initialize the dataset builder.
        
        Args:
            csv_file_path: Path to the CSV file with vulnerability data
            db_path: Path to the SQLite database
            repo_path: Path to the Git repository
        """
        self.csv_file_path = Path(csv_file_path)
        self.db_path = Path(db_path)
        self.repo_path = Path(repo_path)
        self.db = Database(db_path)
        self.git = GitInteraction(str(repo_path))
        
        logger.info(f"Initialized DatasetBuilder with CSV: {csv_file_path}, DB: {db_path}, Repo: {repo_path}")
    
    def create_database_schema(self) -> None:
        """Create the database schema for the vulnerabilities table."""
        # Columns specification
        existing_fields = [
            "COMMIT_HASH", "VULNERABILITY_CVE", "VULNERABILITY_YEAR", "VULNERABILITY_CWE",
            "VULNERABILITY_CATEGORY", "REPO_URL"
        ]
        future_fields = {
            "DESCRIPTION_IN_PATCH": None,
            "VULNERABLE_CODE_BLOCK": None,
            "PATCHED_CODE_BLOCK": None,
            "NUM_FILES_CHANGED": None,
            "NUM_FUNCTIONS_CHANGED": None,
            "NUM_LINES_ADDED": None,
            "NUM_LINES_DELETED": None
        }
        all_fields = existing_fields + list(future_fields.keys())
        
        # Create table definition
        columns = ["id INTEGER PRIMARY KEY AUTOINCREMENT"]
        columns.extend([f"{field} TEXT" for field in all_fields])
        columns.append("UNIQUE(COMMIT_HASH)")  # Add unique constraint on commit hash
        
        # Create the table
        self.db.create_table("vulnerabilities", columns)
        logger.info("Created database schema")
    
    def load_csv_to_database(self) -> None:
        """Load data from CSV file into the database."""
        try:
            # Read CSV file 
            df = pd.read_csv(self.csv_file_path)
            
            # Map the new CSV columns to the expected database columns
            # linux_100.csv has: commit_hash, cve_id, cwe_id
            # We need to map these to: COMMIT_HASH, VULNERABILITY_CVE, VULNERABILITY_CWE
            df_mapped = pd.DataFrame()
            df_mapped['COMMIT_HASH'] = df['commit_hash']
            df_mapped['VULNERABILITY_CVE'] = df['cve_id']
            df_mapped['VULNERABILITY_CWE'] = df['cwe_id']
            # Set default repo_url since linux_100.csv doesn't have this column
            df_mapped['REPO_URL'] = 'https://github.com/torvalds/linux'
            
            # Extract year from CVE ID (e.g., CVE-2024-26589 -> 2024)
            df_mapped['VULNERABILITY_YEAR'] = df_mapped['VULNERABILITY_CVE'].str.extract(r'CVE-(\d{4})')
            
            # Set default category as empty for now
            df_mapped['VULNERABILITY_CATEGORY'] = ''
            
            # Insert data into database (use INSERT OR IGNORE to prevent duplicates)
            for _, row in df_mapped.iterrows():
                self.db.execute('''
                INSERT OR IGNORE INTO vulnerabilities (COMMIT_HASH, VULNERABILITY_CVE, VULNERABILITY_YEAR, VULNERABILITY_CWE, VULNERABILITY_CATEGORY, REPO_URL)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (row['COMMIT_HASH'], row['VULNERABILITY_CVE'], row['VULNERABILITY_YEAR'], 
                      row['VULNERABILITY_CWE'], row['VULNERABILITY_CATEGORY'], row['REPO_URL']))
            
            self.db.commit()
            logger.info(f"Loaded {len(df_mapped)} records from {self.csv_file_path} into database")
        except Exception as e:
            logger.error(f"Error loading CSV to database: {e}")
            raise
    
    def update_cwe_values(self) -> None:
        """Update CWE values to standardized format (CWE-XXX)."""
        try:
            # Fetch all unique VULNERABILITY_CWE values
            cwe_values = self.db.fetch_all("SELECT DISTINCT VULNERABILITY_CWE FROM vulnerabilities")
            
            # Update each CWE value
            for cwe_value in cwe_values:
                # Check if the value is not None and is a string
                if cwe_value[0]:
                    cwe_str = str(cwe_value[0])
                    # If it's already in CWE-XXX format, skip it
                    if cwe_str.startswith('CWE-'):
                        logger.debug(f"CWE value already in correct format: {cwe_str}")
                        continue
                    
                    try:
                        # Try to extract number and format as CWE-XXX
                        cwe_num = str(int(float(cwe_str)))
                        updated_cwe = f"CWE-{cwe_num}"
                        self.db.execute("""
                            UPDATE vulnerabilities
                            SET VULNERABILITY_CWE = ?
                            WHERE VULNERABILITY_CWE = ?
                        """, (updated_cwe, cwe_value[0]))
                        logger.info(f"Updated CWE value: {cwe_str} -> {updated_cwe}")
                    except ValueError:
                        logger.warning(f"Could not convert CWE value: {cwe_value[0]}")
                        continue
            
            self.db.commit()
            logger.info("Updated CWE values to standardized format")
        except Exception as e:
            logger.error(f"Error updating CWE values: {e}")
            raise
    
    def process_commit(self, commit_hash: str) -> None:
        """Process a single commit to extract vulnerability information.
        
        Args:
            commit_hash: Git commit hash to process
        """
        try:
            # Get patch text and extract file information
            patch_text = self.git.get_patch_of_commit(commit_hash)
            if not patch_text:
                logger.warning(f"Could not fetch patch for commit {commit_hash} - commit may not exist in local repo")
                # Still mark as processed with empty data
                self._mark_commit_as_processed(commit_hash, "COMMIT_NOT_FOUND", "", "", 0, 0, 0, 0)
                return
                
            info = self.git.extract_files_and_functions_info(patch_text)
            file_info, vulnerable_code_block, patched_code_block = self.git.build_code_blocks(info, commit_hash)
            
            # Extract additional information
            num_files_changed, num_lines_added, num_lines_deleted = self.git.parse_patch_header(patch_text)
            num_functions_changed = self.git.num_functions_changed(vulnerable_code_block, patched_code_block)
            commit_description = self.git.extract_commit_description(commit_hash)
            
            # Save to database
            self._mark_commit_as_processed(commit_hash, commit_description, vulnerable_code_block, 
                                         patched_code_block, num_files_changed, num_functions_changed, 
                                         num_lines_added, num_lines_deleted)
            
            logger.info(f"Successfully processed commit {commit_hash}")
        except Exception as e:
            logger.error(f"Error processing commit {commit_hash}: {e}")
            # Mark as processed with error information
            self._mark_commit_as_processed(commit_hash, f"ERROR: {str(e)}", "", "", 0, 0, 0, 0)
    
    def _mark_commit_as_processed(self, commit_hash: str, description: str, vulnerable_code: str, 
                                patched_code: str, num_files: int, num_functions: int, 
                                lines_added: int, lines_deleted: int) -> None:
        """Mark a commit as processed in the database."""
        try:
            self.db.execute('''
            UPDATE vulnerabilities
            SET DESCRIPTION_IN_PATCH = ?,
                VULNERABLE_CODE_BLOCK = ?,
                PATCHED_CODE_BLOCK = ?,
                NUM_FILES_CHANGED = ?,
                NUM_FUNCTIONS_CHANGED = ?,
                NUM_LINES_ADDED = ?,
                NUM_LINES_DELETED = ?
            WHERE COMMIT_HASH = ?
            ''', (description, vulnerable_code, patched_code, 
                  num_files, num_functions, lines_added, lines_deleted, commit_hash))
            
            self.db.commit()
        except Exception as e:
            logger.error(f"Error updating database for commit {commit_hash}: {e}")
    
    def process_commits_in_parallel(self, commit_hashes: List[str], max_workers: Optional[int] = None) -> None:
        """Process commits sequentially to avoid SQLite threading issues.
        
        Args:
            commit_hashes: List of commit hashes to process
            max_workers: Maximum number of worker threads (ignored for now)
        """
        logger.info(f"Processing {len(commit_hashes)} commits sequentially")
        
        for i, commit_hash in enumerate(commit_hashes):
            try:
                logger.info(f"Processing commit {i+1}/{len(commit_hashes)}: {commit_hash}")
                self.process_commit(commit_hash)
            except Exception as e:
                logger.error(f"Error processing commit {commit_hash}: {e}")
    
    def update_line_counts(self) -> None:
        """Update the number of lines in the code blocks."""
        try:
            # Check if the columns exist, if not, add them
            for column in ['NUM_LINES_IN_VULNERABLE_CODE_BLOCK', 'NUM_LINES_IN_PATCHED_CODE_BLOCK']:
                if not self.db.column_exists("vulnerabilities", column):
                    self.db.add_column("vulnerabilities", f"{column} INTEGER")
            
            # Fetch all commit hashes and code blocks
            rows = self.db.fetch_all("SELECT COMMIT_HASH, VULNERABLE_CODE_BLOCK, PATCHED_CODE_BLOCK FROM vulnerabilities")
            
            # Update the database with line counts
            for row in rows:
                commit_hash, vulnerable_code_block, patched_code_block = row
                if vulnerable_code_block and patched_code_block:
                    num_lines_vulnerable = len(vulnerable_code_block.split('\n'))
                    num_lines_patched = len(patched_code_block.split('\n'))
                    
                    self.db.execute("""
                        UPDATE vulnerabilities
                        SET NUM_LINES_IN_VULNERABLE_CODE_BLOCK = ?,
                            NUM_LINES_IN_PATCHED_CODE_BLOCK = ?
                        WHERE COMMIT_HASH = ?
                    """, (num_lines_vulnerable, num_lines_patched, commit_hash))
            
            self.db.commit()
            logger.info("Updated line counts in code blocks")
        except Exception as e:
            logger.error(f"Error updating line counts: {e}")
            raise
    
    def clean_incomplete_entries(self) -> None:
        """Delete entries with missing CWE or empty vulnerable code blocks."""
        try:
            # Only remove entries with NULL CWE, but keep entries with empty code blocks
            # so we can see which commits couldn't be processed
            self.db.execute("DELETE FROM vulnerabilities WHERE VULNERABILITY_CWE IS NULL")
            self.db.commit()
            logger.info("Removed entries with NULL CWE from database")
        except Exception as e:
            logger.error(f"Error cleaning database: {e}")
            raise
    
    def build_dataset(self) -> None:
        """Build the complete vulnerability dataset."""
        try:
            logger.info("Starting dataset build process")
            
            # Create database schema
            self.create_database_schema()
            
            # Load data from CSV
            self.load_csv_to_database()
            
            # Update CWE values to standardized format
            self.update_cwe_values()
            
            # Get all commit hashes
            commit_hashes = [row[0] for row in self.db.fetch_all("SELECT COMMIT_HASH FROM vulnerabilities")]
            logger.info(f"Found {len(commit_hashes)} commits to process")
            
            # Process each commit in parallel
            self.process_commits_in_parallel(commit_hashes)
            
            # Update line counts
            self.update_line_counts()
            
            # Clean up incomplete entries
            self.clean_incomplete_entries()
            
            logger.info("Dataset build process completed successfully")
        except Exception as e:
            logger.error(f"Error building dataset: {e}")
            raise
        finally:
            self.db.disconnect()


def main(csv_path: str, db_path: str, repo_path: str) -> None:
    """Main function to build the dataset.
    
    Args:
        csv_path: Path to the CSV file with vulnerability data
        db_path: Path to the SQLite database
        repo_path: Path to the Git repository
    """
    # Setup logging
    log_path = os.path.join(os.path.dirname(db_path), "dataset_builder.log")
    logger = setup_logger("dataset_builder", log_path)
    
    try:
        # Create and run the dataset builder
        builder = DatasetBuilder(csv_path, db_path, repo_path)
        builder.build_dataset()
    except Exception as e:
        logger.error(f"Error in main: {e}", exc_info=True)
        raise 