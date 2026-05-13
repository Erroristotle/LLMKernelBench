"""Advanced evaluator with LangChain integration, job scheduling, and multiple database support."""
import os
import json
import shutil
import logging
import warnings
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from utils.database import Database
from utils.logger import setup_logger

# Fix pydantic import warning
warnings.filterwarnings("ignore", message=".*langchain_core.pydantic_v1.*", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*OUTPUT_PARSING_FAILURE.*")

from models.llm_manager import LLMManager
from models.baseline_evaluator import BaselineEvaluator, evaluate_all_baselines
from scheduler.job_scheduler import JobScheduler, JobState
from utils.config import get_model_db_path, MODELS_CONFIG

logger = logging.getLogger(__name__)

class AdvancedEvaluator:
    """Advanced evaluator with LangChain integration and job scheduling support."""
    
    def __init__(
        self,
        model_name: str,
        database_name: str,
        output_dir: Union[str, Path],
        models_config_file: Union[str, Path] = MODELS_CONFIG,
        max_workers: Optional[int] = None
    ):
        """Initialize the advanced evaluator.
        
        Args:
            model_name: Name of the model to use
            database_name: Name of the database to use (with or without .sqlite extension)
            output_dir: Directory to store output files
            models_config_file: Path to the models configuration file
            max_workers: Maximum number of worker threads
        """
        self.model_name = model_name
        self.database_name = database_name
        self.output_dir = Path(output_dir)
        self.max_workers = max_workers or os.cpu_count() or 4
        
        # Load models configuration
        self.models_config = self._load_models_config(models_config_file)
        
        # Determine database file path
        self.source_db_file = self._get_database_path(database_name)
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # Create model-specific database path
        self.model_db_file = get_model_db_path(f"{model_name}_{database_name}")
        
        # Copy the database for this model if it doesn't exist
        if not self.model_db_file.exists():
            shutil.copy(self.source_db_file, self.model_db_file)
            logger.info(f"Created new database for model {model_name} at {self.model_db_file}")
        
        # Ensure all required columns exist
        from utils.database import Database
        temp_db = Database(self.model_db_file)
        temp_db.add_missing_columns()
        temp_db.disconnect()
        
        # Initialize the appropriate manager based on model type
        self.manager = None
        self.is_baseline = model_name in self.models_config.get('baselines', {})
        
        if self.is_baseline:
            model_config = self.models_config['baselines'][model_name]
            self.manager = BaselineEvaluator(
                db_file=self.model_db_file,
                model_config=model_config,
                model_name=model_name
            )
        else:
            model_config = self.models_config['llms'][model_name]
            self.manager = LLMManager(
                db_file=self.model_db_file,
                model_config=model_config,
                model_name=model_name
            )
        
        # Initialize job scheduler
        self.scheduler = JobScheduler(
            state_dir=self.output_dir / "scheduler" / "state",
            log_dir=self.output_dir / "scheduler" / "logs"
        )
        
        logger.info(f"Initialized AdvancedEvaluator with model: {model_name} on database: {database_name}")
    
    def _load_models_config(self, config_file: Union[str, Path]) -> Dict[str, Any]:
        """Load models configuration from JSON file.
        
        Args:
            config_file: Path to the models configuration file
            
        Returns:
            Dictionary with models configuration
        """
        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Models configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        logger.info(f"Loaded models configuration from {config_path}")
        return config
    
    def _get_database_path(self, database_name: str) -> Path:
        """Get the full path to the database file.
        
        Args:
            database_name: Name of the database (with or without .sqlite extension)
            
        Returns:
            Path object to the database file
        """
        # Add .sqlite extension if not present
        if not database_name.endswith('.sqlite'):
            database_name += '.sqlite'
        
        # Look for the database in the data directory
        db_path = Path("data") / database_name
        
        if not db_path.exists():
            raise FileNotFoundError(f"Database file not found: {db_path}")
        
        return db_path
    
    def run_evaluation(
        self,
        tasks: Optional[List[str]] = None,
        use_scheduler: bool = True,
        resume_job_id: Optional[str] = None
    ) -> Optional[JobState]:
        """Run evaluation for selected tasks.
        
        Args:
            tasks: List of tasks to run (None for default tasks)
            use_scheduler: Whether to use job scheduler
            resume_job_id: Job ID to resume (if any)
            
        Returns:
            JobState object if using scheduler, None otherwise
        """
        if tasks is None:
            if self.is_baseline:
                tasks = ["baseline_evaluation"]
            else:
                # All 7 tasks for LLM evaluation
                tasks = [
                    "is_vulnerable_vuln",
                    "is_vulnerable_patch", 
                    "is_vulnerable_vuln_cve_cwe",
                    "is_vulnerable_patch_cve_cwe",
                    "rank_cwe"
                ]
        
        logger.info(f"Starting evaluation with model {self.model_name} on database {self.database_name}")
        logger.info(f"Tasks to run: {tasks}")
        
        if use_scheduler:
            return self._run_with_scheduler(tasks, resume_job_id)
        else:
            return self._run_direct(tasks)
    
    def _run_with_scheduler(
        self,
        tasks: List[str],
        resume_job_id: Optional[str] = None
    ) -> JobState:
        """Run evaluation using the job scheduler.
        
        Args:
            tasks: List of tasks to run
            resume_job_id: Job ID to resume (if any)
            
        Returns:
            JobState object
        """
        if resume_job_id:
            job = self.scheduler.resume_job(resume_job_id)
            if not job:
                raise ValueError(f"Could not resume job {resume_job_id}")
        else:
            job = self.scheduler.create_job(
                model_name=self.model_name,
                database_name=self.database_name,
                tasks=tasks
            )
        
        # Prepare evaluator kwargs
        evaluator_kwargs = {
            'db_file': str(self.model_db_file),
            'model_config': (self.models_config['baselines'][self.model_name] 
                           if self.is_baseline 
                           else self.models_config['llms'][self.model_name]),
            'model_name': self.model_name
        }
        
        # Choose appropriate evaluator class
        evaluator_class = BaselineEvaluator if self.is_baseline else LLMManager
        
        # Run the job
        self.scheduler.run_job(
            job=job,
            tasks=tasks,
            evaluator_class=evaluator_class,
            evaluator_kwargs=evaluator_kwargs
        )
        
        return job
    
    def _run_direct(self, tasks: List[str]) -> None:
        """Run evaluation directly without job scheduler.
        
        Args:
            tasks: List of tasks to run
        """
        if self.is_baseline:
            self._run_baseline_tasks(tasks)
        else:
            self._run_llm_tasks(tasks)
        
        logger.info("Evaluation completed")
    
    def _run_baseline_tasks(self, tasks: List[str]) -> None:
        """Run baseline evaluation tasks.
        
        Args:
            tasks: List of tasks to run
        """
        if "baseline_evaluation" in tasks:
            logger.info("Running baseline evaluation")
            self.manager.evaluate_vulnerabilities()
            
            # Calculate and log metrics
            metrics = self.manager.calculate_metrics()
            
            # Save metrics to file
            metrics_file = self.output_dir / f"metrics_{self.model_name}_{self.database_name}.json"
            with open(metrics_file, 'w') as f:
                json.dump(metrics, f, indent=2)
            
            logger.info(f"Saved metrics to {metrics_file}")
    
    def _run_llm_tasks(self, tasks: List[str]) -> None:
        """Run LLM evaluation tasks.
        
        Args:
            tasks: List of tasks to run
        """
        # Fetch vulnerability data
        data = self._fetch_data()
        
        # Run selected tasks
        for task_name in tasks:
            if task_name == "is_vulnerable_vuln":
                self._run_task_is_vulnerable_vuln(data)
            elif task_name == "is_vulnerable_patch":
                self._run_task_is_vulnerable_patch(data)
            elif task_name == "is_vulnerable_vuln_cve_cwe":
                self._run_task_is_vulnerable_vuln_cve_cwe(data)
            elif task_name == "is_vulnerable_patch_cve_cwe":
                self._run_task_is_vulnerable_patch_cve_cwe(data)
            elif task_name == "rank_cwe":
                self._run_task_rank_cwe(data)
            else:
                logger.warning(f"Unknown task: {task_name}")
        
        # Update line counts in the database
        if hasattr(self.manager, 'update_line_counts'):
            self.manager.update_line_counts()
        
        # Ensure any pending batched commits are flushed
        if hasattr(self.manager, 'flush_commits'):
            self.manager.flush_commits()
    
    def _fetch_data(self) -> List[Dict[str, Any]]:
        """Fetch vulnerability data from the database.
        
        Returns:
            List of dictionaries with vulnerability data
        """
        db = Database(self.model_db_file)
        
        query = """
        SELECT 
            COMMIT_HASH, 
            VULNERABLE_CODE_BLOCK, 
            PATCHED_CODE_BLOCK, 
            VULNERABILITY_YEAR, 
            DESCRIPTION_IN_PATCH,
            VULNERABILITY_CVE, 
            VULNERABILITY_CWE,
            IS_VULNERABLE_Vuln,
            IS_VULNERABLE_Patch,
            IS_VULNERABLE_Vuln_CVE_CWE,
            IS_VULNERABLE_Patch_CVE_CWE,
            LLM_Ranked_CWE
        FROM vulnerabilities
        """
        
        columns = [
            'commit_hash', 'vulnerable_code_block', 'patched_code_block', 'vulnerability_year',
            'description', 'cve', 'cwe', 'is_vulnerable_vuln', 'is_vulnerable_patch',
            'is_vulnerable_vuln_cve_cwe', 'is_vulnerable_patch_cve_cwe', 'llm_ranked_cwe'
        ]
        
        results = db.fetch_all(query)
        data = [dict(zip(columns, row)) for row in results]
        
        db.disconnect()
        logger.info(f"Fetched {len(data)} vulnerability records from database")
        
        # Count incomplete tasks for reporting
        incomplete_counts = {}
        task_columns = {
            'is_vulnerable_vuln': 'is_vulnerable_vuln',
            'is_vulnerable_patch': 'is_vulnerable_patch', 
            'is_vulnerable_vuln_cve_cwe': 'is_vulnerable_vuln_cve_cwe',
            'is_vulnerable_patch_cve_cwe': 'is_vulnerable_patch_cve_cwe',
            'rank_cwe': 'llm_ranked_cwe'
        }
        
        for task_name, column_name in task_columns.items():
            incomplete_count = sum(1 for item in data if item[column_name] is None or item[column_name] == '')
            incomplete_counts[task_name] = incomplete_count
            
        logger.info(f"Incomplete tasks: {incomplete_counts}")
        return data
    
    def _worker_function(self, func, *args, max_retries: int = 3) -> None:
        """Execute a worker function with retries.
        
        Args:
            func: Function to execute
            *args: Arguments for the function
            max_retries: Maximum number of retry attempts
        """
        retries = 0
        while retries < max_retries:
            try:
                func(*args)
                break
            except Exception as e:
                retries += 1
                logger.error(f"Error processing task, retry {retries}/{max_retries}: {e}")
                if retries == max_retries:
                    logger.error(f"Max retries reached for task execution: {e}")
                    raise
                    logger.error(f"Failed to process commit {args[0]} after {max_retries} retries.")
    
    def _run_task_is_vulnerable_vuln(self, data: List[Dict[str, Any]]) -> None:
        """Run the task for checking if vulnerable code is vulnerable."""
        logger.info("Starting is_vulnerable_vuln task")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for item in data:
                if item['is_vulnerable_vuln'] is None and item['vulnerable_code_block']:
                    futures.append(
                        executor.submit(
                            self._worker_function,
                            self.manager.is_vulnerable_func,
                            item['commit_hash'],
                            item['vulnerable_code_block'],
                            True
                        )
                    )
            
            logger.info(f"Submitting {len(futures)} vulnerable code check tasks")
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error checking vulnerable code: {e}")
    
    def _run_task_is_vulnerable_patch(self, data: List[Dict[str, Any]]) -> None:
        """Run the task for checking if patched code is vulnerable."""
        logger.info("Starting is_vulnerable_patch task")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for item in data:
                if item['is_vulnerable_patch'] is None and item['patched_code_block']:
                    futures.append(
                        executor.submit(
                            self._worker_function,
                            self.manager.is_vulnerable_func,
                            item['commit_hash'],
                            item['patched_code_block'],
                            False
                        )
                    )
            
            logger.info(f"Submitting {len(futures)} patched code check tasks")
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error checking patched code: {e}")
    
    def _run_task_is_vulnerable_vuln_cve_cwe(self, data: List[Dict[str, Any]]) -> None:
        """Run the task for checking if vulnerable code is vulnerable to its CVE/CWE."""
        logger.info("Starting is_vulnerable_vuln_cve_cwe task")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for item in data:
                if item['is_vulnerable_vuln_cve_cwe'] is None and item['vulnerable_code_block'] and item['cve'] and item['cwe']:
                    futures.append(
                        executor.submit(
                            self._worker_function,
                            self.manager.is_vulnerable_to_CVE_CWE,
                            item['commit_hash'],
                            item['vulnerable_code_block'],
                            item['cve'],
                            item['cwe'],
                            True
                        )
                    )
            
            logger.info(f"Submitting {len(futures)} vulnerable CVE/CWE check tasks")
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error checking vulnerable CVE/CWE: {e}")
    
    def _run_task_is_vulnerable_patch_cve_cwe(self, data: List[Dict[str, Any]]) -> None:
        """Run the task for checking if patched code is vulnerable to its CVE/CWE."""
        logger.info("Starting is_vulnerable_patch_cve_cwe task")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for item in data:
                if item['is_vulnerable_patch_cve_cwe'] is None and item['patched_code_block'] and item['cve'] and item['cwe']:
                    futures.append(
                        executor.submit(
                            self._worker_function,
                            self.manager.is_vulnerable_to_CVE_CWE,
                            item['commit_hash'],
                            item['patched_code_block'],
                            item['cve'],
                            item['cwe'],
                            False
                        )
                    )
            
            logger.info(f"Submitting {len(futures)} patched CVE/CWE check tasks")
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error checking patched CVE/CWE: {e}")
    
    def _run_task_rank_cwe(self, data: List[Dict[str, Any]]) -> None:
        """Run the task for ranking CWEs (Common Weakness Enumeration)."""
        logger.info("Starting rank_cwe task")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for item in data:
                if (item['llm_ranked_cwe'] is None or item['llm_ranked_cwe'] == '') and item['vulnerable_code_block']:
                    futures.append(
                        executor.submit(
                            self._worker_function,
                            self.manager.rank_cwe,
                            item['commit_hash'],
                            item['vulnerable_code_block']
                        )
                    )
            
            logger.info(f"Submitting {len(futures)} CWE ranking tasks")
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error ranking CWEs: {e}")

    def get_job_status(self, job_id: str) -> Optional[JobState]:
        """Get the status of a job.
        
        Args:
            job_id: Job ID to check
            
        Returns:
            JobState object if found, None otherwise
        """
        return self.scheduler.get_job_status(job_id)
    
    def list_jobs(self) -> List[JobState]:
        """List all jobs.
        
        Returns:
            List of JobState objects
        """
        return self.scheduler.list_jobs()


def run_evaluation_on_both_databases(
    model_name: str,
    output_dir: str,
    models_config_file: str = MODELS_CONFIG,
    tasks: Optional[List[str]] = None,
    use_scheduler: bool = True
) -> Dict[str, Optional[JobState]]:
    """Run evaluation on both database.sqlite and database_leakagefree.sqlite SEQUENTIALLY.
    
    NOTE: This runs databases ONE AT A TIME to maximize resources per database.
    Each database gets full system resources before moving to the next.
    
    Args:
        model_name: Name of the model to use
        output_dir: Directory to store output files
        models_config_file: Path to the models configuration file
        tasks: List of tasks to run (None for default tasks)
        use_scheduler: Whether to use job scheduler
        
    Returns:
        Dictionary mapping database names to JobState objects
    """
    results = {}
    databases = ["database", "database_leakagefree"]
    
    logger.info(f"=" * 80)
    logger.info(f"SEQUENTIAL EVALUATION: Processing {len(databases)} databases ONE AT A TIME")
    logger.info(f"=" * 80)
    
    for idx, db_name in enumerate(databases, 1):
        logger.info(f"\n{'='*80}")
        logger.info(f"DATABASE {idx}/{len(databases)}: {db_name}.sqlite")
        logger.info(f"Allocating FULL SYSTEM RESOURCES to this database")
        logger.info(f"{'='*80}\n")
        
        evaluator = AdvancedEvaluator(
            model_name=model_name,
            database_name=db_name,
            output_dir=output_dir,
            models_config_file=models_config_file
        )
        
        job_state = evaluator.run_evaluation(
            tasks=tasks,
            use_scheduler=use_scheduler
        )
        
        results[db_name] = job_state
        logger.info(f"\n{'='*80}")
        logger.info(f"COMPLETED: {db_name}.sqlite")
        logger.info(f"{'='*80}\n")
    
    logger.info(f"=" * 80)
    logger.info(f"ALL DATABASES COMPLETED SEQUENTIALLY")
    logger.info(f"=" * 80)
    
    return results


def evaluate_all_models_and_baselines(
    output_dir: str,
    models_config_file: str = MODELS_CONFIG,
    database_name: str = "database",
    tasks: Optional[List[str]] = None,
    use_scheduler: bool = True
) -> Dict[str, Optional[JobState]]:
    """Evaluate all models and baselines on a specific database.
    
    Args:
        output_dir: Directory to store output files
        models_config_file: Path to the models configuration file
        database_name: Name of the database to use
        tasks: List of tasks to run (None for default tasks)
        use_scheduler: Whether to use job scheduler
        
    Returns:
        Dictionary mapping model names to JobState objects
    """
    # Load models configuration
    with open(models_config_file, 'r') as f:
        models_config = json.load(f)
    
    results = {}
    
    # Evaluate LLMs
    for model_name in models_config.get('llms', {}):
        logger.info(f"Starting evaluation with LLM: {model_name}")
        
        evaluator = AdvancedEvaluator(
            model_name=model_name,
            database_name=database_name,
            output_dir=output_dir,
            models_config_file=models_config_file
        )
        
        job_state = evaluator.run_evaluation(
            tasks=tasks,
            use_scheduler=use_scheduler
        )
        
        results[model_name] = job_state
    
    # Evaluate baselines
    for model_name in models_config.get('baselines', {}):
        logger.info(f"Starting evaluation with baseline: {model_name}")
        
        evaluator = AdvancedEvaluator(
            model_name=model_name,
            database_name=database_name,
            output_dir=output_dir,
            models_config_file=models_config_file
        )
        
        job_state = evaluator.run_evaluation(
            tasks=["baseline_evaluation"],
            use_scheduler=use_scheduler
        )
        
        results[model_name] = job_state
    
    return results
