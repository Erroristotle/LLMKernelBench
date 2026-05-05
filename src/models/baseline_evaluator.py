"""Baseline model evaluator for vulnerability detection."""

import logging
import torch
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Tuple
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification, 
    AutoModel, pipeline, RobertaTokenizer, RobertaForSequenceClassification
)
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from utils.database import Database
from utils.logger import setup_logger

logger = logging.getLogger(__name__)

class BaselineEvaluator:
    """Evaluator for baseline vulnerability detection models."""
    
    def __init__(
        self, 
        db_file: Union[str, Path], 
        model_config: Dict[str, Any],
        model_name: str
    ):
        """Initialize the baseline evaluator.
        
        Args:
            db_file: Path to the SQLite database
            model_config: Model configuration dictionary
            model_name: Name of the baseline model to use
        """
        self.db_file = Path(db_file)
        self.model_config = model_config
        self.model_name = model_name
        self.db = Database(self.db_file)
        
        # Initialize the model
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        
        # Create necessary columns in the database
        self.create_columns()
        
        # Initialize the specific baseline model
        self._initialize_model()
        
        logger.info(f"Initialized BaselineEvaluator with model: {model_name}")
    
    def create_columns(self) -> None:
        """Create necessary columns in the database if they do not exist."""
        model_suffix = self.model_name.upper().replace('-', '_')
        columns = [          
            f"{model_suffix}_VULN_PREDICTION INT",
            f"{model_suffix}_PATCH_PREDICTION INT",
            f"{model_suffix}_VULN_PROBABILITY REAL",
            f"{model_suffix}_PATCH_PROBABILITY REAL",
            f"{model_suffix}_VULN_CONFIDENCE REAL",
            f"{model_suffix}_PATCH_CONFIDENCE REAL"
        ]
        
        for column_def in columns:
            column_name = column_def.split()[0]
            # Only add column if it doesn't exist
            if not self.db.column_exists("vulnerabilities", column_name):
                self.db.add_column("vulnerabilities", column_def)
            else:
                logger.debug(f"Column {column_name} already exists, skipping")
    
    def _initialize_model(self) -> None:
        """Initialize the specific baseline model."""
        model_name_hf = self.model_config['model_name']
        
        try:
            # Check if CUDA is available
            device = 0 if torch.cuda.is_available() else -1
            
            # Special handling for different model types
            if 'vulberta' in model_name_hf.lower():
                # VulBERTa uses RoBERTa architecture
                self.tokenizer = RobertaTokenizer.from_pretrained(model_name_hf)
                self.model = RobertaForSequenceClassification.from_pretrained(model_name_hf)
            else:
                # Generic handling for other models
                self.tokenizer = AutoTokenizer.from_pretrained(model_name_hf, trust_remote_code=True)
                self.model = AutoModelForSequenceClassification.from_pretrained(
                    model_name_hf, 
                    trust_remote_code=True
                )
            
            # Move model to appropriate device
            if torch.cuda.is_available():
                self.model = self.model.cuda()
            
            # Create pipeline for easier inference
            self.pipeline = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=device,
                return_all_scores=True
            )
            
            logger.info(f"Initialized baseline model: {model_name_hf}")
            
        except Exception as e:
            logger.error(f"Failed to initialize baseline model {model_name_hf}: {e}")
            raise
    
    def predict_vulnerability(
        self, 
        code_block: str, 
        max_length: int = 512
    ) -> Tuple[int, float, float]:
        """Predict vulnerability for a code block.
        
        Args:
            code_block: Code block to analyze
            max_length: Maximum token length for the model
            
        Returns:
            Tuple of (prediction, probability, confidence)
        """
        try:
            # Truncate code if too long
            inputs = self.tokenizer.encode(code_block, truncation=True, max_length=max_length)
            if len(inputs) > max_length:
                code_block = self.tokenizer.decode(inputs[:max_length], skip_special_tokens=True)
            
            # Get prediction from pipeline
            results = self.pipeline(code_block)
            
            # Extract prediction and probability
            if isinstance(results[0], list):
                # Multiple scores returned
                scores = results[0]
                # Find the score for vulnerability (label 1 or "VULNERABLE")
                vuln_score = None
                for score in scores:
                    if (score['label'] == 'LABEL_1' or 
                        score['label'] == '1' or 
                        'vuln' in score['label'].lower()):
                        vuln_score = score['score']
                        break
                
                if vuln_score is None:
                    # Fallback: use first score
                    vuln_score = scores[0]['score']
                    
                prediction = 1 if vuln_score > 0.5 else 0
                probability = vuln_score
                confidence = abs(vuln_score - 0.5) * 2  # Distance from 0.5, scaled to [0,1]
                
            else:
                # Single score returned
                result = results[0]
                if 'score' in result:
                    probability = result['score']
                    prediction = 1 if probability > 0.5 else 0
                    confidence = abs(probability - 0.5) * 2
                else:
                    prediction = 0
                    probability = 0.5
                    confidence = 0.0
            
            return prediction, probability, confidence
            
        except Exception as e:
            logger.error(f"Error predicting vulnerability: {e}")
            return 0, 0.5, 0.0
    
    def evaluate_vulnerabilities(self) -> None:
        """Evaluate vulnerabilities on all code blocks in the database."""
        logger.info(f"Starting baseline evaluation with {self.model_name}")
        
        # Fetch vulnerability data
        data = self._fetch_data()
        
        model_suffix = self.model_name.upper().replace('-', '_')
        
        for item in data:
            commit_hash = item['commit_hash']
            
            # Evaluate vulnerable code block
            if item['vulnerable_code_block']:
                try:
                    pred, prob, conf = self.predict_vulnerability(item['vulnerable_code_block'])
                    
                    self.db.execute(f"""
                        UPDATE vulnerabilities
                        SET {model_suffix}_VULN_PREDICTION = ?, 
                            {model_suffix}_VULN_PROBABILITY = ?,
                            {model_suffix}_VULN_CONFIDENCE = ?
                        WHERE COMMIT_HASH = ?
                    """, (pred, prob, conf, commit_hash))
                    
                    logger.debug(f"Vulnerable code prediction for {commit_hash}: {pred} (prob: {prob:.3f})")
                    
                except Exception as e:
                    logger.error(f"Error evaluating vulnerable code for {commit_hash}: {e}")
            
            # Evaluate patched code block
            if item['patched_code_block']:
                try:
                    pred, prob, conf = self.predict_vulnerability(item['patched_code_block'])
                    
                    self.db.execute(f"""
                        UPDATE vulnerabilities
                        SET {model_suffix}_PATCH_PREDICTION = ?, 
                            {model_suffix}_PATCH_PROBABILITY = ?,
                            {model_suffix}_PATCH_CONFIDENCE = ?
                        WHERE COMMIT_HASH = ?
                    """, (pred, prob, conf, commit_hash))
                    
                    logger.debug(f"Patched code prediction for {commit_hash}: {pred} (prob: {prob:.3f})")
                    
                except Exception as e:
                    logger.error(f"Error evaluating patched code for {commit_hash}: {e}")
        
        # Commit all changes
        self.db.commit()
        logger.info(f"Completed baseline evaluation with {self.model_name}")
    
    def _fetch_data(self) -> List[Dict[str, Any]]:
        """Fetch vulnerability data from the database.
        
        Returns:
            List of dictionaries with vulnerability data
        """
        query = """
        SELECT 
            COMMIT_HASH, 
            VULNERABLE_CODE_BLOCK, 
            PATCHED_CODE_BLOCK, 
            VULNERABILITY_CVE, 
            VULNERABILITY_CWE
        FROM vulnerabilities
        """
        
        columns = ['commit_hash', 'vulnerable_code_block', 'patched_code_block', 'cve', 'cwe']
        
        results = self.db.fetch_all(query)
        data = [dict(zip(columns, row)) for row in results]
        
        logger.info(f"Fetched {len(data)} vulnerability records from database")
        return data
    
    def calculate_metrics(self) -> Dict[str, float]:
        """Calculate performance metrics for the baseline model.
        
        Returns:
            Dictionary with performance metrics
        """
        model_suffix = self.model_name.upper().replace('-', '_')
        
        # Fetch predictions and ground truth
        query = f"""
        SELECT 
            {model_suffix}_VULN_PREDICTION,
            {model_suffix}_PATCH_PREDICTION,
            1 as vuln_ground_truth,
            0 as patch_ground_truth
        FROM vulnerabilities
        WHERE {model_suffix}_VULN_PREDICTION IS NOT NULL 
        AND {model_suffix}_PATCH_PREDICTION IS NOT NULL
        """
        
        results = self.db.fetch_all(query)
        
        if not results:
            logger.warning("No predictions found for metrics calculation")
            return {}
        
        vuln_predictions = [row[0] for row in results]
        patch_predictions = [row[1] for row in results]
        vuln_ground_truth = [row[2] for row in results]  # All vulnerable code should be predicted as vulnerable
        patch_ground_truth = [row[3] for row in results]  # All patched code should be predicted as not vulnerable
        
        # Calculate metrics for vulnerable code detection
        vuln_accuracy = accuracy_score(vuln_ground_truth, vuln_predictions)
        vuln_precision = precision_score(vuln_ground_truth, vuln_predictions, zero_division=0)
        vuln_recall = recall_score(vuln_ground_truth, vuln_predictions, zero_division=0)
        vuln_f1 = f1_score(vuln_ground_truth, vuln_predictions, zero_division=0)
        
        # Calculate metrics for patched code detection (should predict 0)
        patch_accuracy = accuracy_score(patch_ground_truth, patch_predictions)
        patch_precision = precision_score(patch_ground_truth, patch_predictions, pos_label=0, zero_division=0)
        patch_recall = recall_score(patch_ground_truth, patch_predictions, pos_label=0, zero_division=0)
        patch_f1 = f1_score(patch_ground_truth, patch_predictions, pos_label=0, zero_division=0)
        
        metrics = {
            'vuln_accuracy': vuln_accuracy,
            'vuln_precision': vuln_precision,
            'vuln_recall': vuln_recall,
            'vuln_f1': vuln_f1,
            'patch_accuracy': patch_accuracy,
            'patch_precision': patch_precision,
            'patch_recall': patch_recall,
            'patch_f1': patch_f1,
            'overall_accuracy': (vuln_accuracy + patch_accuracy) / 2,
            'overall_f1': (vuln_f1 + patch_f1) / 2
        }
        
        logger.info(f"Metrics for {self.model_name}:")
        for metric, value in metrics.items():
            logger.info(f"  {metric}: {value:.4f}")
        
        return metrics


def evaluate_baseline_model(
    model_name: str,
    db_file: str,
    model_config: Dict[str, Any]
) -> Dict[str, float]:
    """Evaluate a single baseline model.
    
    Args:
        model_name: Name of the baseline model
        db_file: Path to the SQLite database
        model_config: Model configuration dictionary
        
    Returns:
        Dictionary with performance metrics
    """
    try:
        evaluator = BaselineEvaluator(db_file, model_config, model_name)
        evaluator.evaluate_vulnerabilities()
        metrics = evaluator.calculate_metrics()
        return metrics
        
    except Exception as e:
        logger.error(f"Error evaluating baseline model {model_name}: {e}")
        return {}


def evaluate_all_baselines(
    db_file: str,
    baselines_config: Dict[str, Dict[str, Any]]
) -> Dict[str, Dict[str, float]]:
    """Evaluate all baseline models.
    
    Args:
        db_file: Path to the SQLite database
        baselines_config: Configuration for all baseline models
        
    Returns:
        Dictionary mapping model names to their metrics
    """
    all_metrics = {}
    
    for model_name, model_config in baselines_config.items():
        logger.info(f"Evaluating baseline model: {model_name}")
        metrics = evaluate_baseline_model(model_name, db_file, model_config)
        all_metrics[model_name] = metrics
    
    return all_metrics
