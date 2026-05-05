#!/usr/bin/env python3
"""
Script to clean up malformed CWE ranking data and prepare for strict rerun.
This will clear all existing CWE rankings to ensure clean, consistent format.
"""

import sqlite3
import json
import sys
from pathlib import Path

def clean_cwe_data():
    """Clean up malformed CWE data in all model databases."""
    
    models = ["gemini", "deepseek", "qwen", "llama", "starcoder", "mistral", "gemma"]
    databases = ["database", "database_leakagefree"]
    
    print("🧹 CLEANING MALFORMED CWE DATA")
    print("=" * 60)
    
    total_cleaned = 0
    databases_found = 0
    
    for model in models:
        for database in databases:
            db_file = Path(f"data/{model}_{database}.sqlite")
            
            if not db_file.exists():
                print(f"⚠️  {model}/{database}: Database not found")
                continue
            
            databases_found += 1
            
            try:
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                
                # Check if column exists
                cursor.execute("PRAGMA table_info(vulnerabilities)")
                columns = [col[1] for col in cursor.fetchall()]
                
                if 'LLM_Ranked_CWE' not in columns:
                    print(f"📝 {model}/{database}: Adding LLM_Ranked_CWE column")
                    cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN LLM_Ranked_CWE TEXT")
                
                # Count existing records
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE LLM_Ranked_CWE IS NOT NULL AND LLM_Ranked_CWE != ''")
                existing_count = cursor.fetchone()[0]
                
                # Clear all existing CWE rankings to force clean rerun
                cursor.execute("UPDATE vulnerabilities SET LLM_Ranked_CWE = NULL")
                conn.commit()
                
                total_cleaned += existing_count
                print(f"🗑️  {model}/{database}: Cleared {existing_count} existing CWE rankings")
                
                conn.close()
                
            except Exception as e:
                print(f"❌ {model}/{database}: Error - {e}")
    
    print(f"\n📊 SUMMARY:")
    print(f"   Databases processed: {databases_found}")
    print(f"   Total CWE entries cleared: {total_cleaned}")
    print(f"   Ready for clean rerun with strict formatting")

def validate_cwe_format():
    """Validate existing CWE data format (for testing after rerun)."""
    
    models = ["gemini", "deepseek", "qwen", "llama", "starcoder", "mistral", "gemma"] 
    databases = ["database", "database_leakagefree"]
    
    print("\n🔍 VALIDATING CWE FORMAT")
    print("=" * 60)
    
    valid_count = 0
    invalid_count = 0
    
    for model in models:
        for database in databases:
            db_file = Path(f"data/{model}_{database}.sqlite")
            
            if not db_file.exists():
                continue
            
            try:
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT COMMIT_HASH, LLM_Ranked_CWE 
                    FROM vulnerabilities 
                    WHERE LLM_Ranked_CWE IS NOT NULL AND LLM_Ranked_CWE != ''
                    LIMIT 5
                """)
                
                results = cursor.fetchall()
                
                for commit_hash, cwe_data in results:
                    try:
                        # Try to parse as JSON
                        parsed = json.loads(cwe_data)
                        if isinstance(parsed, list) and len(parsed) == 5:
                            # Check each CWE format
                            all_valid = all(
                                isinstance(cwe, str) and cwe.startswith('CWE-') and cwe[4:].isdigit()
                                for cwe in parsed
                            )
                            if all_valid:
                                valid_count += 1
                                print(f"✅ {model}/{database} - {commit_hash[:8]}: {cwe_data}")
                            else:
                                invalid_count += 1
                                print(f"❌ {model}/{database} - {commit_hash[:8]}: Invalid CWE format")
                        else:
                            invalid_count += 1
                            print(f"❌ {model}/{database} - {commit_hash[:8]}: Not 5-item list")
                    except json.JSONDecodeError:
                        invalid_count += 1
                        print(f"❌ {model}/{database} - {commit_hash[:8]}: Invalid JSON")
                
                conn.close()
                
            except Exception as e:
                print(f"❌ {model}/{database}: Validation error - {e}")
    
    print(f"\n📊 VALIDATION SUMMARY:")
    print(f"   Valid CWE entries: {valid_count}")
    print(f"   Invalid CWE entries: {invalid_count}")
    print(f"   Format compliance: {(valid_count/(valid_count+invalid_count)*100) if (valid_count+invalid_count) > 0 else 0:.1f}%")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Clean and validate CWE ranking data")
    parser.add_argument("--clean", action="store_true", help="Clean existing malformed CWE data")
    parser.add_argument("--validate", action="store_true", help="Validate CWE format")
    
    args = parser.parse_args()
    
    if args.clean:
        clean_cwe_data()
    elif args.validate:
        validate_cwe_format()
    else:
        print("Usage: python clean_cwe_data.py [--clean|--validate]")
        print("  --clean: Remove all existing CWE data for fresh rerun")
        print("  --validate: Check format of existing CWE data")