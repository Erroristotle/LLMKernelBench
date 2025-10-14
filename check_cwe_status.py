#!/usr/bin/env python3
"""
Quick script to check CWE ranking completion status across all models and databases.
This provides a detailed report of what's complete and what needs to be run.
"""

import sqlite3
import sys
from pathlib import Path
import json

def check_cwe_completion():
    """Check CWE ranking completion status for all models and databases."""
    
    # Models and databases to check
    models = ["gemini", "deepseek", "qwen", "llama", "starcoder", "mistral", "gemma"]
    databases = ["database", "database_leakagefree"]
    
    print("🔍 CWE RANKING COMPLETION STATUS")
    print("=" * 70)
    
    total_combinations = len(models) * len(databases)
    found_databases = 0
    incomplete_combinations = []
    
    results = {}
    
    for model in models:
        results[model] = {}
        
        for database in databases:
            db_file = Path(f"data/{model}_{database}.sqlite")
            
            if not db_file.exists():
                status = "❌ DB Missing"
                completed = 0
                total = 0
                completion_rate = 0.0
                # Always add missing databases to incomplete list
                incomplete_combinations.append(f"{model}/{database}")
            else:
                found_databases += 1
                try:
                    conn = sqlite3.connect(db_file)
                    cursor = conn.cursor()
                    
                    # Check total records
                    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
                    total = cursor.fetchone()[0]
                    
                    # Check if LLM_Ranked_CWE column exists
                    cursor.execute("PRAGMA table_info(vulnerabilities)")
                    columns = [col[1] for col in cursor.fetchall()]
                    
                    if 'LLM_Ranked_CWE' not in columns:
                        status = "❌ Column Missing"
                        completed = 0
                        completion_rate = 0.0
                        incomplete_combinations.append(f"{model}/{database}")
                    else:
                        # Check completed CWE rankings
                        cursor.execute("""
                            SELECT COUNT(*) FROM vulnerabilities 
                            WHERE LLM_Ranked_CWE IS NOT NULL 
                            AND LLM_Ranked_CWE != '' 
                            AND LLM_Ranked_CWE != 'Error: No response'
                        """)
                        completed = cursor.fetchone()[0]
                        
                        completion_rate = (completed / total * 100) if total > 0 else 0
                        
                        if completion_rate >= 100:
                            status = "✅ Complete"
                            # ALWAYS add to incomplete to force re-run if needed
                            incomplete_combinations.append(f"{model}/{database}")
                        elif completion_rate > 0:
                            status = f"🟡 {completion_rate:.1f}%"
                            incomplete_combinations.append(f"{model}/{database}")
                        else:
                            status = "❌ Not Started"
                            incomplete_combinations.append(f"{model}/{database}")
                    
                    conn.close()
                        
                except Exception as e:
                    status = f"❌ Error: {e}"
                    completed = 0
                    total = 0
                    completion_rate = 0.0
                    incomplete_combinations.append(f"{model}/{database}")
            
            results[model][database] = {
                "status": status,
                "completed": completed,
                "total": total,
                "rate": completion_rate
            }
    
    # Print table
    print(f"{'Model':<12} {'Regular DB':<15} {'Leakage-Free DB':<15}")
    print("-" * 45)
    
    for model in models:
        regular_status = results[model]["database"]["status"]
        leakage_status = results[model]["database_leakagefree"]["status"]
        print(f"{model:<12} {regular_status:<15} {leakage_status:<15}")
    
    print("\n" + "=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    print(f"Total model/database combinations: {total_combinations}")
    print(f"Found databases: {found_databases}")
    print(f"Will run CWE ranking on: {len(incomplete_combinations)} combinations")
    print(f"Missing databases: {total_combinations - found_databases}")
    
    if incomplete_combinations:
        print(f"\n🔄 COMBINATIONS TO PROCESS:")
        for combo in incomplete_combinations:
            model, database = combo.split('/')
            result = results[model][database]
            print(f"   • {combo}: {result['completed']}/{result['total']} ({result['rate']:.1f}%)")
        
        print(f"\n📋 COMMANDS TO RUN CWE RANKING:")
        print("# Run all CWE rankings (including re-runs):")
        print("sbatch --partition=GPU --nodelist=str-gpu31 --gres=gpu:2 --time=48:00:00 --mem=100G run_cwe_ranking.sh")
        print("\n# Or run individual commands:")
        for combo in incomplete_combinations:
            model, database = combo.split('/')
            print(f"python main.py evaluate {model} --database {database} --tasks rank_cwe")
    
    else:
        print("\n⚠️  No databases found to process!")
    
    return found_databases > 0

if __name__ == "__main__":
    all_complete = check_cwe_completion()
    sys.exit(0 if all_complete else 1)