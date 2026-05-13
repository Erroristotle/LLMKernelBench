#!/usr/bin/env python3
"""
Script to check completion status of evaluations across all models and databases.
This helps identify which tasks are incomplete and need to be resumed.
"""

import sqlite3
import os
from pathlib import Path
import json

def check_database_completion(db_path):
    """Check completion status for a single database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get total count
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_count = cursor.fetchone()[0]
        
        # Check each task column
        task_columns = {
            'IS_VULNERABLE_Vuln': 'Vulnerable code check',
            'IS_VULNERABLE_Patch': 'Patched code check', 
            'IS_VULNERABLE_Vuln_CVE_CWE': 'Vulnerable CVE/CWE check',
            'IS_VULNERABLE_Patch_CVE_CWE': 'Patched CVE/CWE check',
            'LLM_Ranked_CWE': 'CWE ranking'
        }
        
        completion_status = {}
        
        for column, description in task_columns.items():
            # Check if column exists
            cursor.execute("PRAGMA table_info(vulnerabilities)")
            columns = [info[1] for info in cursor.fetchall()]
            
            if column not in columns:
                completion_status[column] = {
                    'description': description,
                    'completed': 0,
                    'total': total_count,
                    'percentage': 0.0,
                    'missing': total_count
                }
            else:
                # Count non-null and non-empty entries
                cursor.execute(f"SELECT COUNT(*) FROM vulnerabilities WHERE {column} IS NOT NULL AND {column} != ''")
                completed = cursor.fetchone()[0]
                
                completion_status[column] = {
                    'description': description,
                    'completed': completed,
                    'total': total_count,
                    'percentage': (completed / total_count * 100) if total_count > 0 else 0.0,
                    'missing': total_count - completed
                }
        
        conn.close()
        return completion_status, total_count
        
    except Exception as e:
        print(f"Error checking {db_path}: {e}")
        return {}, 0

def main():
    """Main function to check all model databases."""
    data_dir = Path("data")
    
    print("=" * 80)
    print("EVALUATION COMPLETION STATUS REPORT")
    print("=" * 80)
    
    # Find all model databases
    model_databases = []
    for db_file in data_dir.glob("*.sqlite"):
        if "_database" in db_file.name or "_database_leakagefree" in db_file.name:
            model_databases.append(db_file)
    
    if not model_databases:
        print("No model databases found in data/ directory")
        return
    
    # Sort databases by model name
    model_databases.sort()
    
    for db_path in model_databases:
        print(f"\n📁 Database: {db_path.name}")
        print("-" * 60)
        
        completion_status, total_count = check_database_completion(db_path)
        
        if not completion_status:
            print("   ❌ Could not read database")
            continue
            
        print(f"   Total records: {total_count}")
        print()
        
        incomplete_tasks = []
        
        for column, status in completion_status.items():
            percentage = status['percentage']
            completed = status['completed']
            missing = status['missing']
            description = status['description']
            
            if percentage == 100.0:
                status_icon = "✅"
            elif percentage > 0:
                status_icon = "🟡"
            else:
                status_icon = "❌"
            
            print(f"   {status_icon} {description:<30} {completed:>4}/{total_count:<4} ({percentage:>6.1f}%)")
            
            if missing > 0:
                incomplete_tasks.append({
                    'column': column,
                    'description': description,
                    'missing': missing
                })
        
        if incomplete_tasks:
            print("\n   🔄 INCOMPLETE TASKS:")
            for task in incomplete_tasks:
                print(f"      • {task['description']}: {task['missing']} missing")
        else:
            print("\n   🎉 ALL TASKS COMPLETED!")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    # Generate command suggestions
    models_with_incomplete = set()
    databases_with_incomplete = set()
    
    for db_path in model_databases:
        completion_status, _ = check_database_completion(db_path)
        
        has_incomplete = False
        for status in completion_status.values():
            if status['missing'] > 0:
                has_incomplete = True
                break
        
        if has_incomplete:
            # Extract model name and database type
            db_name = db_path.stem
            if "_database_leakagefree" in db_name:
                model_name = db_name.replace("_database_leakagefree", "")
                db_type = "database_leakagefree"
            elif "_database" in db_name:
                model_name = db_name.replace("_database", "")
                db_type = "database"
            else:
                continue
                
            models_with_incomplete.add(model_name)
            databases_with_incomplete.add(db_type)
    
    if models_with_incomplete:
        print(f"\n🔄 Models with incomplete evaluations: {', '.join(sorted(models_with_incomplete))}")
        print(f"🗃️  Databases with incomplete evaluations: {', '.join(sorted(databases_with_incomplete))}")
        
        print("\n📋 SUGGESTED COMMANDS TO RESUME:")
        for model in sorted(models_with_incomplete):
            print(f"   python main.py evaluate {model} --both-databases")
            
    else:
        print("\n🎉 ALL EVALUATIONS COMPLETED!")

if __name__ == "__main__":
    main()