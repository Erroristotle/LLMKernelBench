"""Job scheduler for cluster execution with resume capability."""

import os
import json
import logging
import time
import signal
import sys
import psutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import traceback

from utils.database import Database
from utils.logger import setup_logger

logger = logging.getLogger(__name__)

@dataclass
class JobState:
    """Data class for job state tracking."""
    job_id: str
    model_name: str
    database_name: str
    current_task: Optional[str] = None
    current_commit_hash: Optional[str] = None
    completed_tasks: List[str] = None
    completed_commits: Dict[str, List[str]] = None
    start_time: Optional[str] = None
    last_update: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed, paused
    error_message: Optional[str] = None
    progress: Dict[str, int] = None
    
    def __post_init__(self):
        if self.completed_tasks is None:
            self.completed_tasks = []
        if self.completed_commits is None:
            self.completed_commits = {}
        if self.progress is None:
            self.progress = {}

class JobScheduler:
    """Job scheduler for managing LLM evaluation tasks with resume capability."""
    
    def __init__(
        self,
        state_dir: Union[str, Path] = "scheduler/state",
        log_dir: Union[str, Path] = "scheduler/logs"
    ):
        """Initialize the job scheduler.
        
        Args:
            state_dir: Directory to store job state files
            log_dir: Directory to store log files
        """
        self.state_dir = Path(state_dir)
        self.log_dir = Path(log_dir)
        
        # Create directories
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.current_job: Optional[JobState] = None
        self.shutdown_requested = False
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("Initialized JobScheduler")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_requested = True
        if self.current_job:
            self.current_job.status = "paused"
            self._save_job_state(self.current_job)
    
    def create_job(
        self,
        model_name: str,
        database_name: str,
        tasks: List[str],
        job_id: Optional[str] = None
    ) -> JobState:
        """Create a new job.
        
        Args:
            model_name: Name of the model to use
            database_name: Name of the database to use
            tasks: List of tasks to execute
            job_id: Optional job ID (generated if not provided)
            
        Returns:
            JobState object
        """
        if job_id is None:
            job_id = f"{model_name}_{database_name}_{int(time.time())}"
        
        job = JobState(
            job_id=job_id,
            model_name=model_name,
            database_name=database_name,
            start_time=datetime.now().isoformat(),
            last_update=datetime.now().isoformat()
        )
        
        # Initialize progress tracking for each task
        for task in tasks:
            job.progress[task] = 0
            job.completed_commits[task] = []
        
        self._save_job_state(job)
        logger.info(f"Created job {job_id} for model {model_name} on database {database_name}")
        
        return job
    
    def resume_job(self, job_id: str) -> Optional[JobState]:
        """Resume a job from its saved state.
        
        Args:
            job_id: Job ID to resume
            
        Returns:
            JobState object if found, None otherwise
        """
        state_file = self.state_dir / f"{job_id}.json"
        
        if not state_file.exists():
            logger.error(f"Job state file not found: {state_file}")
            return None
        
        try:
            with open(state_file, 'r') as f:
                state_data = json.load(f)
            
            job = JobState(**state_data)
            job.status = "running"
            job.last_update = datetime.now().isoformat()
            
            self._save_job_state(job)
            logger.info(f"Resumed job {job_id}")
            
            return job
            
        except Exception as e:
            logger.error(f"Error resuming job {job_id}: {e}")
            return None
    
    def list_jobs(self) -> List[JobState]:
        """List all jobs.
        
        Returns:
            List of JobState objects
        """
        jobs = []
        
        for state_file in self.state_dir.glob("*.json"):
            try:
                with open(state_file, 'r') as f:
                    state_data = json.load(f)
                
                job = JobState(**state_data)
                jobs.append(job)
                
            except Exception as e:
                logger.error(f"Error loading job state from {state_file}: {e}")
        
        # Sort by start time
        jobs.sort(key=lambda x: x.start_time or "")
        
        return jobs
    
    def get_job_status(self, job_id: str) -> Optional[JobState]:
        """Get the status of a specific job.
        
        Args:
            job_id: Job ID to check
            
        Returns:
            JobState object if found, None otherwise
        """
        state_file = self.state_dir / f"{job_id}.json"
        
        if not state_file.exists():
            return None
        
        try:
            with open(state_file, 'r') as f:
                state_data = json.load(f)
            
            return JobState(**state_data)
            
        except Exception as e:
            logger.error(f"Error getting job status for {job_id}: {e}")
            return None
    
    def _save_job_state(self, job: JobState) -> None:
        """Save job state to disk.
        
        Args:
            job: JobState object to save
        """
        state_file = self.state_dir / f"{job.job_id}.json"
        job.last_update = datetime.now().isoformat()
        
        try:
            with open(state_file, 'w') as f:
                json.dump(asdict(job), f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving job state for {job.job_id}: {e}")
    
    def _get_incomplete_commits(
        self,
        job: JobState,
        task: str,
        db_file: Path
    ) -> List[str]:
        """Get list of commits that haven't been processed for a specific task.
        
        Args:
            job: JobState object
            task: Task name
            db_file: Database file path
            
        Returns:
            List of commit hashes that need processing
        """
        db = Database(db_file)
        
        # Define column mappings for different tasks
        task_columns = {
            "is_vulnerable_vuln": "IS_VULNERABLE_Vuln",
            "is_vulnerable_patch": "IS_VULNERABLE_Patch", 
            "is_vulnerable_vuln_cve_cwe": "IS_VULNERABLE_Vuln_CVE_CWE",
            "is_vulnerable_patch_cve_cwe": "IS_VULNERABLE_Patch_CVE_CWE",
            "rank_cwe": "LLM_Ranked_CWE"
        }
        
        column = task_columns.get(task)
        if not column:
            logger.warning(f"Unknown task: {task}")
            return []
        
        # Get commits where the task hasn't been completed
        query = f"""
        SELECT COMMIT_HASH 
        FROM vulnerabilities 
        WHERE ({column} IS NULL OR {column} = '')
        AND VULNERABLE_CODE_BLOCK IS NOT NULL
        """
        
        results = db.fetch_all(query)
        incomplete_commits = [row[0] for row in results]
        
        # Remove commits that are already completed for this task
        completed_for_task = job.completed_commits.get(task, [])
        incomplete_commits = [c for c in incomplete_commits if c not in completed_for_task]
        
        db.disconnect()
        
        logger.debug(f"Found {len(incomplete_commits)} incomplete commits for task {task}")
        return incomplete_commits
    
    def run_job(
        self,
        job: JobState,
        tasks: List[str],
        evaluator_class,
        evaluator_kwargs: Dict[str, Any]
    ) -> None:
        """Run a job with the specified tasks.
        
        Args:
            job: JobState object
            tasks: List of tasks to execute
            evaluator_class: Evaluator class to use
            evaluator_kwargs: Keyword arguments for evaluator initialization
        """
        self.current_job = job
        job.status = "running"
        self._save_job_state(job)
        
        # Setup job-specific logger
        log_file = self.log_dir / f"{job.job_id}.log"
        job_logger = setup_logger(f"job_{job.job_id}", str(log_file))
        
        try:
            # Initialize evaluator
            evaluator = evaluator_class(**evaluator_kwargs)
            
            for task in tasks:
                if self.shutdown_requested:
                    logger.info("Shutdown requested, pausing job")
                    job.status = "paused"
                    break
                
                if task in job.completed_tasks:
                    job_logger.info(f"Task {task} already completed, skipping")
                    continue
                
                job_logger.info(f"Starting task: {task}")
                job.current_task = task
                self._save_job_state(job)
                
                # Get incomplete commits for this task
                db_file = Path(evaluator_kwargs['db_file'])
                incomplete_commits = self._get_incomplete_commits(job, task, db_file)
                
                if not incomplete_commits:
                    job_logger.info(f"No incomplete commits for task {task}")
                    job.completed_tasks.append(task)
                    job.progress[task] = 100
                    self._save_job_state(job)
                    continue
                
                # Process commits for this task
                total_commits = len(incomplete_commits)
                processed_commits = 0
                
                for commit_hash in incomplete_commits:
                    if self.shutdown_requested:
                        logger.info("Shutdown requested during task execution")
                        break
                    
                    try:
                        job.current_commit_hash = commit_hash
                        self._save_job_state(job)
                        
                        # Execute the specific task
                        self._execute_task(evaluator, task, commit_hash, db_file)
                        
                        # Mark commit as completed for this task
                        if task not in job.completed_commits:
                            job.completed_commits[task] = []
                        job.completed_commits[task].append(commit_hash)
                        
                        processed_commits += 1
                        job.progress[task] = int((processed_commits / total_commits) * 100)
                        
                        # Save state periodically
                        if processed_commits % 10 == 0:
                            self._save_job_state(job)
                            job_logger.info(f"Task {task}: {processed_commits}/{total_commits} commits processed")
                        
                    except Exception as e:
                        job_logger.error(f"Error processing commit {commit_hash} for task {task}: {e}")
                        job_logger.error(traceback.format_exc())
                        # Continue with next commit
                        continue
                
                if not self.shutdown_requested:
                    job.completed_tasks.append(task)
                    job.progress[task] = 100
                    job_logger.info(f"Completed task: {task}")
                
                job.current_commit_hash = None
                self._save_job_state(job)
            
            # Update final job status
            if self.shutdown_requested:
                job.status = "paused"
                job_logger.info("Job paused due to shutdown request")
            elif len(job.completed_tasks) == len(tasks):
                job.status = "completed"
                job_logger.info("Job completed successfully")
            else:
                job.status = "failed"
                job_logger.error("Job failed to complete all tasks")
            
        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            job_logger.error(f"Job failed with error: {e}")
            job_logger.error(traceback.format_exc())
        
        finally:
            job.current_task = None
            job.current_commit_hash = None
            self._save_job_state(job)
            self.current_job = None
    
    def _execute_task(
        self,
        evaluator,
        task: str,
        commit_hash: str,
        db_file: Path
    ) -> None:
        """Execute a specific task for a commit.
        
        Args:
            evaluator: Evaluator instance
            task: Task name
            commit_hash: Commit hash to process
            db_file: Database file path
        """
        # Get the data for this commit
        db = Database(db_file)
        
        query = """
        SELECT 
            COMMIT_HASH,
            VULNERABLE_CODE_BLOCK,
            PATCHED_CODE_BLOCK,
            VULNERABILITY_CVE,
            VULNERABILITY_CWE,
            DESCRIPTION_IN_PATCH
        FROM vulnerabilities
        WHERE COMMIT_HASH = ?
        """
        
        result = db.fetch_one(query, (commit_hash,))
        db.disconnect()
        
        if not result:
            logger.warning(f"No data found for commit {commit_hash}")
            return
        
        commit_hash, vuln_code, patch_code, cve, cwe, description = result
        
        # Execute the appropriate task
        try:
            if task == "is_vulnerable_vuln" and vuln_code:
                evaluator.is_vulnerable_func(commit_hash, vuln_code, True)
            elif task == "is_vulnerable_patch" and patch_code:
                evaluator.is_vulnerable_func(commit_hash, patch_code, False)
            elif task == "is_vulnerable_vuln_cve_cwe" and vuln_code and cve and cwe:
                evaluator.is_vulnerable_to_CVE_CWE(commit_hash, vuln_code, cve, cwe, True)
            elif task == "is_vulnerable_patch_cve_cwe" and patch_code and cve and cwe:
                evaluator.is_vulnerable_to_CVE_CWE(commit_hash, patch_code, cve, cwe, False)
            elif task == "rank_cwe" and vuln_code:
                evaluator.rank_cwe(commit_hash, vuln_code)
            else:
                logger.warning(f"Cannot execute task {task} for commit {commit_hash} - missing required data")
                
        except Exception as e:
            logger.error(f"Error executing task {task} for commit {commit_hash}: {e}")
            raise
    
    def cleanup_completed_jobs(self, days_old: int = 30) -> None:
        """Clean up job state files for completed jobs older than specified days.
        
        Args:
            days_old: Number of days old for cleanup
        """
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        
        for state_file in self.state_dir.glob("*.json"):
            try:
                # Check file modification time
                if state_file.stat().st_mtime < cutoff_time:
                    with open(state_file, 'r') as f:
                        state_data = json.load(f)
                    
                    job = JobState(**state_data)
                    
                    # Only clean up completed jobs
                    if job.status == "completed":
                        state_file.unlink()
                        logger.info(f"Cleaned up completed job state: {job.job_id}")
                        
                        # Also clean up log file if it exists
                        log_file = self.log_dir / f"{job.job_id}.log"
                        if log_file.exists():
                            log_file.unlink()
                            
            except Exception as e:
                logger.error(f"Error cleaning up job state file {state_file}: {e}")
    
    def check_and_resume_incomplete_jobs(self) -> List[JobState]:
        """Check for any incomplete jobs and prepare them for resumption.
        
        Returns:
            List of incomplete JobState objects that can be resumed
        """
        incomplete_jobs = []
        
        for state_file in self.state_dir.glob("*.json"):
            try:
                with open(state_file, 'r') as f:
                    state_data = json.load(f)
                
                job = JobState(**state_data)
                
                # Check if job is in a resumable state
                if job.status in ["running", "paused"] and job.current_task:
                    # Verify the job is actually incomplete by checking the database
                    if self._job_has_remaining_work(job):
                        incomplete_jobs.append(job)
                        logger.info(f"Found incomplete job: {job.job_id} (model: {job.model_name}, db: {job.database_name})")
                
            except Exception as e:
                logger.error(f"Error checking job state from {state_file}: {e}")
        
        return incomplete_jobs
    
    def _job_has_remaining_work(self, job: JobState) -> bool:
        """Check if a job has remaining work to do by querying the database.
        
        Args:
            job: JobState object to check
            
        Returns:
            True if there's remaining work, False otherwise
        """
        try:
            from utils.config import get_model_db_path
            db_file = get_model_db_path(f"{job.model_name}_{job.database_name}")
            
            if not db_file.exists():
                logger.warning(f"Database file not found for job {job.job_id}: {db_file}")
                return False
            
            # Check each task for incomplete work
            for task in ["is_vulnerable_vuln", "is_vulnerable_patch", "is_vulnerable_vuln_cve_cwe", 
                        "is_vulnerable_patch_cve_cwe", "rank_cwe"]:
                incomplete_commits = self._get_incomplete_commits(job, task, db_file)
                if incomplete_commits:
                    logger.debug(f"Job {job.job_id} has {len(incomplete_commits)} incomplete commits for task {task}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking remaining work for job {job.job_id}: {e}")
            return False
    
    def force_commit_all_databases(self) -> None:
        """Force commit all database connections to ensure data persistence."""
        logger.info("Forcing commit on all database connections...")
        
        # Get all model database files
        try:
            from utils.config import get_model_db_path
            from pathlib import Path
            
            # Find all model database files
            data_dir = Path("data")
            model_db_files = []
            
            if data_dir.exists():
                model_db_files.extend(data_dir.glob("*_database.sqlite"))
                model_db_files.extend(data_dir.glob("*_database_leakagefree.sqlite"))
            
            for db_file in model_db_files:
                try:
                    db = Database(db_file)
                    db.commit()
                    db.disconnect()
                    logger.debug(f"Committed database: {db_file}")
                except Exception as e:
                    logger.error(f"Error committing database {db_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Error during force commit: {e}")


def main():
    """Main function for running the job scheduler as a standalone script."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Job Scheduler for VulnLLMEval")
    parser.add_argument("--list", action="store_true", help="List all jobs")
    parser.add_argument("--status", type=str, help="Get status of specific job")
    parser.add_argument("--resume", type=str, help="Resume specific job")
    parser.add_argument("--cleanup", type=int, help="Clean up completed jobs older than N days")
    
    args = parser.parse_args()
    
    scheduler = JobScheduler()
    
    if args.list:
        jobs = scheduler.list_jobs()
        print(f"Found {len(jobs)} jobs:")
        for job in jobs:
            print(f"  {job.job_id}: {job.status} ({job.model_name} on {job.database_name})")
    
    elif args.status:
        job = scheduler.get_job_status(args.status)
        if job:
            print(f"Job {args.status}:")
            print(f"  Status: {job.status}")
            print(f"  Model: {job.model_name}")
            print(f"  Database: {job.database_name}")
            print(f"  Current task: {job.current_task}")
            print(f"  Completed tasks: {job.completed_tasks}")
            print(f"  Progress: {job.progress}")
        else:
            print(f"Job {args.status} not found")
    
    elif args.resume:
        job = scheduler.resume_job(args.resume)
        if job:
            print(f"Resumed job {args.resume}")
        else:
            print(f"Failed to resume job {args.resume}")
    
    elif args.cleanup:
        scheduler.cleanup_completed_jobs(args.cleanup)
        print(f"Cleaned up completed jobs older than {args.cleanup} days")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
