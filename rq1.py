import pandas as pd
import sqlite3
import os
import json
def fetch_ranking_data(db_file):
    """Fetch CWE ranking data from the database."""
    conn = sqlite3.connect(db_file)
    query = """
        SELECT 
            LLM_Ranked_CWE,
            VULNERABILITY_CWE
        FROM vulnerabilities
        WHERE LLM_Ranked_CWE IS NOT NULL AND VULNERABILITY_CWE IS NOT NULL
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def fetch_classification_data(db_file):
    """Fetch SVD classification data from the database."""
    conn = sqlite3.connect(db_file)
    query = """
        SELECT 
            id,
            VULNERABILITY_CWE,
            IS_VULNERABLE_Vuln,
            IS_VULNERABLE_Patch,
            IS_VULNERABLE_Vuln_CVE_CWE,
            IS_VULNERABLE_Patch_CVE_CWE
        FROM vulnerabilities
    """
    df = pd.read_sql_query(query, conn)
    conn.close()

    df_clean = pd.DataFrame()

    for idx, row in df.iterrows():

        try:
            # Handle NaN values before converting to int
            vuln_pred = int(row['IS_VULNERABLE_Vuln']) if pd.notna(row['IS_VULNERABLE_Vuln']) else -10
            vuln_pred_cwe = int(row['IS_VULNERABLE_Vuln_CVE_CWE']) if pd.notna(row['IS_VULNERABLE_Vuln_CVE_CWE']) else -10
            patch_pred = int(row['IS_VULNERABLE_Patch']) if pd.notna(row['IS_VULNERABLE_Patch']) else -10
            patch_pred_cwe = int(row['IS_VULNERABLE_Patch_CVE_CWE']) if pd.notna(row['IS_VULNERABLE_Patch_CVE_CWE']) else -10

            vuln_data = {
                "id": row['id'],
                "CWE": row['VULNERABILITY_CWE'],
                "Label": 1,
                "Prediction": vuln_pred,
                "Prediction_CWE": vuln_pred_cwe
            }

            patch_data = {
                "id": row['id'],
                "CWE": row['VULNERABILITY_CWE'],
                "Label": 0,
                "Prediction": patch_pred,
                "Prediction_CWE": patch_pred_cwe
            }
        except Exception as e:
            print(f"Error processing row {idx}: {e}")
            print(row, db_file)

            vuln_data = {
                "id": row['id'],
                "CWE": row['VULNERABILITY_CWE'],
                "Label": 1,
                "Prediction": -10,
                "Prediction_CWE": -10
            }

            patch_data = {
                "id": row['id'],
                "CWE": row['VULNERABILITY_CWE'],
                "Label": 0,
                "Prediction": -10,
                "Prediction_CWE": -10
            }

        df_clean = pd.concat([df_clean, pd.DataFrame([vuln_data, patch_data])], ignore_index=True)

    return df_clean

def load_cwe_hierarchy():
    try:
        with open('./cwe_hierarchy.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("Error: CWE hierarchy file not found")
        return None

def build_cwe_relationships():
    """Build CWE relationship mappings from hierarchy."""
    hierarchy = load_cwe_hierarchy()
    if not hierarchy:
        return {}, {}, {}
    
    # Maps to store relationships
    parent_map = {}  # cwe_id -> parent_id
    children_map = {}  # cwe_id -> [child_ids]
    root_map = {}  # cwe_id -> root_pillar_id
    
    def traverse(node, parent_id=None, root_id=None):
        if 'id' in node:
            cwe_id = node['id']
            
            # Set parent relationship
            if parent_id:
                parent_map[cwe_id] = parent_id
                if parent_id not in children_map:
                    children_map[parent_id] = []
                children_map[parent_id].append(cwe_id)
            
            # Set root pillar (top-level categories)
            if parent_id is None:  # This is a root pillar
                root_id = cwe_id
            root_map[cwe_id] = root_id
            
            # Recurse through children
            for child in node.get('children', []):
                traverse(child, cwe_id, root_id)
    
    # Process the hierarchy
    for pillar in hierarchy.get('children', []):
        traverse(pillar)
    
    return parent_map, children_map, root_map

def get_cwe_relationship_score(pred_cwe, true_cwe, parent_map, children_map, root_map):
    """Calculate HPS score between predicted and true CWE based on their relationship."""
    if pred_cwe == true_cwe:
        return 1.0  # Exact match
    
    # Check parent relationship (pred is parent of true)
    # Using children_map: if pred_cwe has true_cwe as one of its children
    if pred_cwe in children_map and true_cwe in children_map[pred_cwe]:
        return 0.8
    
    # Check child relationship (pred is child of true) 
    # Using children_map: if true_cwe has pred_cwe as one of its children
    if true_cwe in children_map and pred_cwe in children_map[true_cwe]:
        return 0.7
    
    # Check sibling relationship (same direct parent)
    if (pred_cwe in parent_map and true_cwe in parent_map and 
        parent_map[pred_cwe] == parent_map[true_cwe]):
        return 0.6
    
    # Check same root category (same pillar)
    if (pred_cwe in root_map and true_cwe in root_map and 
        root_map[pred_cwe] == root_map[true_cwe]):
        return 0.4
    
    return 0.0  # No relationship

def calculate_hps(predictions, truths):
    """Calculate Hierarchical Proximity Score (HPS) for CWE predictions."""
    parent_map, children_map, root_map = build_cwe_relationships()
    
    if not parent_map:  # No hierarchy available
        return 0
    
    total_score = 0
    total_predictions = 0
    
    for pred, truth in zip(predictions, truths):
        # Parse predicted CWEs
        if isinstance(pred, str):
            try:
                pred_list = json.loads(pred)
            except json.JSONDecodeError:
                pred_list = []
        else:
            pred_list = []
            
        # Parse ground truth CWEs
        truth_list = parse_vulnerability_cwe(truth)
        
        if truth_list and pred_list:  # Only count if both have valid CWEs
            # For each predicted CWE, find the best score against any true CWE
            for pred_cwe in pred_list:
                best_score = 0
                for true_cwe in truth_list:
                    score = get_cwe_relationship_score(pred_cwe, true_cwe, parent_map, children_map, root_map)
                    best_score = max(best_score, score)
                total_score += best_score
                total_predictions += 1
    
    return (total_score / total_predictions * 100) if total_predictions > 0 else 0
    

def parse_vulnerability_cwe(cwe_field):
    """Parse the VULNERABILITY_CWE field which can contain multiple CWEs in JSON format."""
    if isinstance(cwe_field, str):
        try:
            # Parse JSON array like ["CWE-1", "CWE-2"]
            cwe_list = json.loads(cwe_field)
            if isinstance(cwe_list, list):
                return cwe_list
            else:
                return [str(cwe_list)]  # Single CWE as string
        except json.JSONDecodeError:
            # Fallback for non-JSON format
            return [cwe_field.strip()]
    return []

def calculate_top_k_accuracy(predictions, truths, k=5):
    """Calculate top-k accuracy for CWE predictions."""
    correct = 0
    total = 0
    
    for pred, truth in zip(predictions, truths):
        # Parse predicted CWEs
        if isinstance(pred, str):
            try:
                pred_list = json.loads(pred)
            except json.JSONDecodeError:
                print(f"Error decoding JSON: {pred}")
                pred_list = []
        else:
            print(f"Unexpected type for predictions: {type(pred)}")
            pred_list = []
            
        # Parse ground truth CWEs
        truth_list = parse_vulnerability_cwe(truth)
        
        if truth_list:  # Only count if there are ground truth CWEs
            total += 1
            # Check if any ground truth CWE is in top-k predictions
            top_k_preds = pred_list[:k] if len(pred_list) >= k else pred_list
            if any(t in top_k_preds for t in truth_list):
                correct += 1
    
    return (correct / total * 100) if total > 0 else 0

def calculate_mrr(predictions, truths):
    """Calculate Mean Reciprocal Rank (MRR) for CWE predictions."""
    mrr = 0
    total = 0
    
    for pred, truth in zip(predictions, truths):
        # Parse predicted CWEs
        if isinstance(pred, str):
            try:
                pred_list = json.loads(pred)
            except json.JSONDecodeError:
                print(f"Error decoding JSON: {pred}")
                pred_list = []
        else:
            pred_list = []
            
        # Parse ground truth CWEs
        truth_list = parse_vulnerability_cwe(truth)
        
        if truth_list:  # Only count if there are ground truth CWEs
            total += 1
            # Find the highest rank (lowest index) of any correct prediction
            best_rank = float('inf')
            for rank, p in enumerate(pred_list, start=1):
                if p in truth_list:
                    best_rank = min(best_rank, rank)
                    break
            
            if best_rank != float('inf'):
                mrr += 1 / best_rank
    
    return (mrr / total * 100) if total > 0 else 0


def process_database(db_file, llm_name):
    """Process a single database and calculate CWE ranking metrics."""
    df = fetch_ranking_data(db_file)

    if df.empty:
        print(f"No data available to calculate metrics in {db_file}.")
        return None

    # Calculate metrics for CWE only
    top_1_accuracy = calculate_top_k_accuracy(df['LLM_Ranked_CWE'], df['VULNERABILITY_CWE'], k=1)
    top_2_accuracy = calculate_top_k_accuracy(df['LLM_Ranked_CWE'], df['VULNERABILITY_CWE'], k=2)
    top_3_accuracy = calculate_top_k_accuracy(df['LLM_Ranked_CWE'], df['VULNERABILITY_CWE'], k=3)
    top_4_accuracy = calculate_top_k_accuracy(df['LLM_Ranked_CWE'], df['VULNERABILITY_CWE'], k=4)
    top_5_accuracy = calculate_top_k_accuracy(df['LLM_Ranked_CWE'], df['VULNERABILITY_CWE'], k=5)
    mrr_cwe = calculate_mrr(df['LLM_Ranked_CWE'], df['VULNERABILITY_CWE'])
    hps_score = calculate_hps(df['LLM_Ranked_CWE'], df['VULNERABILITY_CWE'])

    # Create DataFrame with CWE metrics
    metrics_df = pd.DataFrame({
        'Model': [llm_name],
        'Top-1 (%)': [round(top_1_accuracy, 1)],
        'Top-2 (%)': [round(top_2_accuracy, 1)],
        'Top-3 (%)': [round(top_3_accuracy, 1)],
        'Top-4 (%)': [round(top_4_accuracy, 1)],
        'Top-5 (%)': [round(top_5_accuracy, 1)],
        'MRR (%)': [round(mrr_cwe, 1)],
        'HPS (%)': [round(hps_score, 1)]
    })

    return metrics_df

def join_datasets(pdb_files, lfdb_files):

    """Loads all sqlite databases and stores the results in a pandas DataFrame."""

    results_task1 = pd.DataFrame()
    results_task2 = pd.DataFrame()

    for model in pdb_files.keys():

        model_name = model
        database = "PBD"
        metrics_task1 = fetch_classification_data(pdb_files[model])
        metrics_task2 = process_database(pdb_files[model], model_name)
        metrics_task1['Model'] = model_name
        metrics_task1['Database'] = database
        metrics_task2['Database'] = database

        if results_task1.empty:
            results_task1 = metrics_task1
        else:
            results_task1 = pd.concat([results_task1, metrics_task1], ignore_index=True)

        if results_task2.empty:
            results_task2 = metrics_task2
        else:
            results_task2 = pd.concat([results_task2, metrics_task2], ignore_index=True)

    for model in lfdb_files.keys():

        model_name = model
        database = "LFDB"
        metrics_task1 = fetch_classification_data(lfdb_files[model])
        metrics_task2 = process_database(lfdb_files[model], model_name)
        metrics_task1['Model'] = model_name
        metrics_task1['Database'] = database
        metrics_task2['Database'] = database

        if results_task1.empty:
            results_task1 = metrics_task1
        else:
            results_task1 = pd.concat([results_task1, metrics_task1], ignore_index=True)

        if results_task2.empty:
            results_task2 = metrics_task2
        else:
            results_task2 = pd.concat([results_task2, metrics_task2], ignore_index=True)

    return results_task1, results_task2


import pandas as pd
from sklearn.metrics import accuracy_score, recall_score, precision_score

import pandas as pd
from sklearn.metrics import accuracy_score, recall_score, precision_score

def create_tables_task_1(df: pd.DataFrame):
    """
    Creates LaTeX tables for:
      1–2. Prediction Summary per Model (Prediction / Prediction_CWE) — split by Database
      3–8. Metric tables (Accuracy, Recall, Precision, PPR) — split by Database (PBD/LFD)
    """

    # --- Helper to compute metrics ---
    def compute_metrics(group, label_col, pred_col):
        y_true = group[label_col]
        y_pred = group[pred_col]
        return pd.Series({
            "Accuracy": round(accuracy_score(y_true, y_pred) * 100, 1),
            "Recall": round(recall_score(y_true, y_pred, zero_division=0) * 100, 1),
            "Precision": round(precision_score(y_true, y_pred, zero_division=0) * 100, 1),
            "PPR": round(y_pred.mean() * 100, 1)
        })

    # Normalize CWE column if list
    df["CWE"] = df["CWE"].apply(lambda x: x[0] if isinstance(x, list) else x)

    # --- 1️⃣ Prediction Summary per Model (with PBD/LFD split) ---
    summary_rows = []
    summary_rows_cwe = []

    for model, group in df.groupby("Model"):
        row_pred = {"Model": model}
        row_pred_cwe = {"Model": model}

        for db in ["PBD", "LFDB"]:
            db_group = group[group["Database"] == db]
            total = len(db_group)
            if total == 0:
                row_pred.update({f"Predicted_{db}": "-", f"Abstained_{db}": "-", f"Invalid_{db}": "-"})
                row_pred_cwe.update({f"Predicted_CWE_{db}": "-", f"Abstained_CWE_{db}": "-", f"Invalid_CWE_{db}": "-"})
                continue

            # --- Prediction ---
            predicted_count = db_group["Prediction"].isin([0, 1]).sum()
            abstained_count = (db_group["Prediction"] == -1).sum()
            invalid_count = (~db_group["Prediction"].isin([0, 1, -1])).sum()

            row_pred.update({
                f"Predicted_{db}": f"{predicted_count} ({predicted_count / total * 100:.1f}\\%)",
                f"Abstained_{db}": f"{abstained_count} ({abstained_count / total * 100:.1f}\\%)",
                f"Invalid_{db}": f"{invalid_count} ({invalid_count / total * 100:.1f}\\%)"
            })

            # --- Prediction_CWE ---
            predicted_count_cwe = db_group["Prediction_CWE"].isin([0, 1]).sum()
            abstained_count_cwe = (db_group["Prediction_CWE"] == -1).sum()
            invalid_count_cwe = (~db_group["Prediction_CWE"].isin([0, 1, -1])).sum()

            row_pred_cwe.update({
                f"Predicted_CWE_{db}": f"{predicted_count_cwe} ({predicted_count_cwe / total * 100:.1f}\\%)",
                f"Abstained_CWE_{db}": f"{abstained_count_cwe} ({abstained_count_cwe / total * 100:.1f}\\%)",
                f"Invalid_CWE_{db}": f"{invalid_count_cwe} ({invalid_count_cwe / total * 100:.1f}\\%)"
            })

        summary_rows.append(row_pred)
        summary_rows_cwe.append(row_pred_cwe)

    pred_summary = pd.DataFrame(summary_rows)
    pred_summary_cwe = pd.DataFrame(summary_rows_cwe)

    print("\n% ===== Prediction Summary per Model (split by Database) =====")
    print(pred_summary.to_latex(index=False, escape=False))

    print("\n% ===== Prediction_CWE Summary per Model (split by Database) =====")
    print(pred_summary_cwe.to_latex(index=False, escape=False))

    # --- Filter valid rows for metric computation ---
    df = df[df["Prediction"].isin([0, 1]) & df["Prediction_CWE"].isin([0, 1])]

    # --- 2️⃣ Metrics (Accuracy, Recall, Precision, PPR) per Model/CWE ---
    def metrics_by_database(df, group_cols, label_col, pred_col):
        rows = []
        for keys, group in df.groupby(group_cols):
            if not isinstance(keys, tuple):
                keys = (keys,)
            row = {col: val for col, val in zip(group_cols, keys)}

            for db in ["PBD", "LFDB"]:
                db_group = group[group["Database"] == db]
                if len(db_group) == 0:
                    row.update({
                        f"Accuracy_{db}": "-", f"Recall_{db}": "-",
                        f"Precision_{db}": "-", f"PPR_{db}": "-"
                    })
                else:
                    metrics = compute_metrics(db_group, label_col, pred_col)
                    for m in ["Accuracy", "Recall", "Precision", "PPR"]:
                        row[f"{m}_{db}"] = metrics[m]
            rows.append(row)
        return pd.DataFrame(rows)

    tables = {
        "Prediction_per_Model": metrics_by_database(df, ["Model"], "Label", "Prediction"),
        "Prediction_per_CWE": metrics_by_database(df, ["CWE"], "Label", "Prediction"),
        "Prediction_per_Model_CWE": metrics_by_database(df, ["Model", "CWE"], "Label", "Prediction"),
        "PredictionCWE_per_Model": metrics_by_database(df, ["Model"], "Label", "Prediction_CWE"),
        "PredictionCWE_per_CWE": metrics_by_database(df, ["CWE"], "Label", "Prediction_CWE"),
        "PredictionCWE_per_Model_CWE": metrics_by_database(df, ["Model", "CWE"], "Label", "Prediction_CWE"),
    }

    for name, table in tables.items():
        print(f"\n% ===== {name} =====")
        print(table.to_latex(index=False, escape=False, float_format="%.1f"))

    return {"summaries": (pred_summary, pred_summary_cwe), "metrics": tables}


def create_tables_task_2(df: pd.DataFrame):
    """
    Creates LaTeX tables for Task 2 results.
    """

    print("\n% ===== Task 2 Results =====")

    # Aggregate rows with same model but different Database using the rule:
    # 1. For each metric, multiply its values by the size of the original dataset
    # 2. Sum the results for each model
    # 3. Divide by the total size of the datasets for that model

    pbd_size = 314
    lfdb_size = 103

    aggregated_rows = []

    for model, group in df.groupby("Model"):

        total_size = 0
        agg_metrics = {
            'Top-1 (%)': 0,
            'Top-2 (%)': 0,
            'Top-3 (%)': 0,
            'Top-4 (%)': 0,
            'Top-5 (%)': 0,
            'MRR (%)': 0,
            'HPS (%)': 0
        }

        for _, row in group.iterrows():
            size = pbd_size if row['Database'] == 'PBD' else lfdb_size
            total_size += size

            for metric in agg_metrics.keys():
                agg_metrics[metric] += row[metric] * size

        # Finalize aggregation by dividing by total size
        for metric in agg_metrics.keys():
            agg_metrics[metric] = round(agg_metrics[metric] / total_size, 1)

        agg_metrics['Model'] = model
        aggregated_rows.append(agg_metrics)

    aggregated_df = pd.DataFrame(aggregated_rows)

    print(aggregated_df.to_latex(index=False, float_format="%.1f"))

    return aggregated_df

db_paths = {
    "main": './data/database.sqlite',
    "leakagefree": './data/database_leakagefree.sqlite'
}

main_model_files = {
    'CodeLlama': './output/database_codellama_database.sqlite',
    'DeepSeek': './output/database_deepseek_database.sqlite',
    'Llama3.1': './output/database_llama_database.sqlite',
    'Mistral': './output/database_mistral_database.sqlite',
    'Qwen2.5-Coder': './output/database_qwen3_coder_database.sqlite',
    'StarCoder2': './output/database_starcoder_database.sqlite',
    "GPT-4.1-mini": './output/database_gpt-4.1_database.sqlite'
}

# Define leakage-free dataset model files
leakagefree_model_files = {
    'CodeLlama': './output/leakagefree/database_codellama_database_leakagefree.sqlite',
    'DeepSeek': './output/leakagefree/database_deepseek_database_leakagefree.sqlite', 
    'Llama3.1': './output/leakagefree/database_llama_database_leakagefree.sqlite',
    'Mistral': './output/leakagefree/database_mistral_database_leakagefree.sqlite',
    'Qwen2.5-Coder': './output/leakagefree/database_qwen3_coder_database_leakagefree.sqlite',
    'StarCoder2': './output/leakagefree/database_starcoder_database_leakagefree.sqlite',
    "GPT-4.1-mini": './output/leakagefree/database_gpt-4.1_database_leakagefree.sqlite'
}

results_task1, results_task2 = join_datasets(main_model_files, leakagefree_model_files)

# Generate and print tables for Task 1 (Classification)
print("\n" + "="*80)
print("TASK 1: CLASSIFICATION METRICS")
print("="*80)
create_tables_task_1(results_task1)

# Generate and print tables for Task 2 (Ranking)
print("\n" + "="*80)
print("TASK 2: RANKING METRICS")
print("="*80)
create_tables_task_2(results_task2)