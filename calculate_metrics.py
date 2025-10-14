#!/usr/bin/env python3
import sqlite3
import pandas as pd
from datetime import datetime

# Connect to the SQLite database
db_path = '/users/azibaeir/Research/VulnLLMEval-SANER/data/database_leakagefree.sqlite'
conn = sqlite3.connect(db_path)

# Query all vulnerability data
query = "SELECT * FROM vulnerabilities"
df = pd.read_sql_query(query, conn)

# Close connection
conn.close()

# Calculate metrics
total_vulnerabilities = len(df)
unique_cves = df['VULNERABILITY_CVE'].nunique()
unique_cwes = df['VULNERABILITY_CWE'].nunique()

# Convert numeric columns from text to numbers
df['NUM_FILES_CHANGED'] = pd.to_numeric(df['NUM_FILES_CHANGED'], errors='coerce')
df['NUM_FUNCTIONS_CHANGED'] = pd.to_numeric(df['NUM_FUNCTIONS_CHANGED'], errors='coerce')
df['NUM_LINES_ADDED'] = pd.to_numeric(df['NUM_LINES_ADDED'], errors='coerce')
df['NUM_LINES_DELETED'] = pd.to_numeric(df['NUM_LINES_DELETED'], errors='coerce')

# Calculate averages
avg_files_changed = df['NUM_FILES_CHANGED'].mean()
avg_functions_changed = df['NUM_FUNCTIONS_CHANGED'].mean()
avg_lines_vulnerable = df['NUM_LINES_IN_VULNERABLE_CODE_BLOCK'].mean()
avg_lines_patched = df['NUM_LINES_IN_PATCHED_CODE_BLOCK'].mean()
avg_lines_added = df['NUM_LINES_ADDED'].mean()
avg_lines_deleted = df['NUM_LINES_DELETED'].mean()

# Extract years from CVEs or use VULNERABILITY_YEAR
years = []
for _, row in df.iterrows():
    year = row['VULNERABILITY_YEAR']
    if pd.isna(year) or not year:
        # Try to extract from CVE if year is not available
        cve = row['VULNERABILITY_CVE']
        if pd.notna(cve) and cve.startswith('CVE-'):
            try:
                year = cve.split('-')[1]
            except (IndexError, AttributeError):
                year = None
    years.append(year)

valid_years = [int(y) for y in years if y and str(y).isdigit() and 1990 <= int(y) <= datetime.now().year]
year_range = f"{min(valid_years)}-{max(valid_years)}" if valid_years else "N/A"

# Print results
print(f"Total Vulnerabilities: {total_vulnerabilities}")
print(f"Unique CVEs: {unique_cves}")
print(f"Unique CWEs: {unique_cwes}")
print(f"Average Files Changed: {avg_files_changed:.2f}")
print(f"Average Functions Changed: {avg_functions_changed:.2f}")
print(f"Year Range: {year_range}")
print(f"Average Lines in Vulnerable Code: {avg_lines_vulnerable:.2f}")
print(f"Average Lines in Patched Code: {avg_lines_patched:.2f}")
print(f"Average Lines Added: {avg_lines_added:.2f}")
print(f"Average Lines Deleted: {avg_lines_deleted:.2f}") 