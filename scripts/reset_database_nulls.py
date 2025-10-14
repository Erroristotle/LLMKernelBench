#!/usr/bin/env python3
"""
Script to reset NULL and empty values in database for reprocessing.
This allows CodeLlama (and other models) to process all incomplete records.
"""

import argparse
import sqlite3
import logging
from pathlib import Path
from typing import List

def setup_logging():
    """Setup basic logging."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    return logging.getLogger(__name__)

def reset_null_and_empty_values(db_path: str, columns: List[str] = None, dry_run: bool = False):
    """Reset NULL and empty string values to ensure reprocessing.
    
    Args:
        db_path: Path to the database file
        columns: List of specific columns to reset (None for default columns)
        dry_run: If True, only show what would be done without making changes
    """
    logger = setup_logging()
    
    if columns is None:
        # Default columns that should be reprocessed if NULL or empty
        columns = [
            'IS_VULNERABLE_Vuln',
            'IS_VULNERABLE_Patch', 
            'IS_VULNERABLE_Vuln_CVE_CWE',
            'IS_VULNERABLE_Patch_CVE_CWE',
            'Patched_Block_LLM',
            'Patched_Block_LLM_F',
            'LLM_Ranked_CWE',
            'IS_VULNERABLE_Vuln_PROB',
            'IS_VULNERABLE_Patch_PROB',
            'IS_VULNERABLE_Vuln_CVE_CWE_PROB',
            'IS_VULNERABLE_Patch_CVE_CWE_PROB'
        ]
    
    db_file = Path(db_path)
    if not db_file.exists():
        logger.error(f"Database file not found: {db_file}")
        return
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    try:
        # Check which columns exist
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        
        # Filter to only existing columns
        columns_to_reset = [col for col in columns if col in existing_columns]
        
        if not columns_to_reset:
            logger.warning("No matching columns found in database")
            return
        
        logger.info(f"Processing database: {db_file}")
        logger.info(f"Columns to reset: {columns_to_reset}")
        
        total_updates = 0
        
        for column in columns_to_reset:
            # Count records that will be affected
            cursor.execute(f"""
                SELECT COUNT(*) FROM vulnerabilities 
                WHERE {column} IS NULL OR {column} = '' OR {column} = -1
            """)
            count = cursor.fetchone()[0]
            
            if count > 0:
                logger.info(f"Column {column}: {count} records to reset")
                
                if not dry_run:
                    # Reset NULL, empty strings, and -1 values to NULL
                    cursor.execute(f"""
                        UPDATE vulnerabilities 
                        SET {column} = NULL 
                        WHERE {column} IS NULL OR {column} = '' OR {column} = -1
                    """)
                    
                total_updates += count
            else:
                logger.info(f"Column {column}: No records to reset")
        
        if not dry_run and total_updates > 0:
            conn.commit()
            logger.info(f"✓ Reset {total_updates} records across {len(columns_to_reset)} columns")
        elif dry_run:
            logger.info(f"DRY RUN: Would reset {total_updates} records")
        else:
            logger.info("No records needed resetting")
            
    except Exception as e:
        logger.error(f"Error processing database: {e}")
        conn.rollback()
    finally:
        conn.close()

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Reset NULL and empty values in database for reprocessing"
    )
    parser.add_argument('database', help='Path to database file')
    parser.add_argument('--columns', nargs='*', help='Specific columns to reset')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    
    args = parser.parse_args()
    
    reset_null_and_empty_values(args.database, args.columns, args.dry_run)

if __name__ == "__main__":
    main()