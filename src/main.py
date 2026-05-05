#!/usr/bin/env python3
"""
Main entry point for VulnLLMEval with advanced features.

This script provides a comprehensive interface for:
1. Running LLM evaluations with LangChain filtering
2. Managing baseline model evaluations  
3. Job scheduling for cluster execution
4. Dual database support (database.sqlite and database_leakagefree.sqlite)
5. Resume capability for interrupted jobs
"""

import argparse
import sys
import os
import json
import logging
from pathlib import Path
from typing import List, Optional

from utils.logger import setup_logger
from utils.config import MODELS_CONFIG
from evaluation.advanced_evaluator import (
    AdvancedEvaluator, 
    run_evaluation_on_both_databases,
    evaluate_all_models_and_baselines
)
from scheduler.job_scheduler import JobScheduler

logger = logging.getLogger(__name__)

def load_models_config(config_file: str = str(MODELS_CONFIG)) -> dict:
    """Load models configuration."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Models configuration file not found: {config_file}")
    
    with open(config_file, 'r') as f:
        return json.load(f)

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="VulnLLMEval - Advanced LLM Vulnerability Evaluation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run evaluation with a specific LLM on ONE database (RECOMMENDED - full resources)
  python main.py evaluate gpt --database database
  
  # Run evaluation on BOTH databases (SEQUENTIAL - one at a time)
  python main.py evaluate gpt --both-databases
  
  # Run on leakage-free database
  python main.py evaluate gpt --database database_leakagefree
  
  # Run all models and baselines on database_leakagefree.sqlite
  python main.py evaluate-all --database database_leakagefree
  
  # Resume a specific job
  python main.py resume <job_id>
  
  # List all jobs
  python main.py list-jobs
  
  # Check job status
  python main.py status <job_id>

NOTE: By default, evaluations run on ONE database at a time with MAXIMUM RESOURCES.
      Results are saved to database in REAL-TIME (every sample committed immediately).
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Evaluate command
    eval_parser = subparsers.add_parser('evaluate', help='Run evaluation with a specific model')
    eval_parser.add_argument('model', help='Model name to use for evaluation')
    eval_parser.add_argument('--database', default='database', 
                           help='Database to use (database or database_leakagefree)')
    eval_parser.add_argument('--both-databases', action='store_true',
                           help='Run evaluation on both databases')
    eval_parser.add_argument('--output-dir', default='results',
                           help='Directory to store output files')
    eval_parser.add_argument('--models-config', default=str(MODELS_CONFIG),
                           help='Path to models configuration file')
    eval_parser.add_argument('--tasks', nargs='*',
                           help='Specific tasks to run (default: all tasks)')
    eval_parser.add_argument('--no-scheduler', action='store_true',
                           help='Run without job scheduler (direct execution)')
    eval_parser.add_argument('--max-workers', type=int,
                           help='Maximum number of worker threads')
    eval_parser.add_argument('--force-reprocess', action='store_true',
                           help='Reprocess NULL and empty values in database columns')
    eval_parser.add_argument('--deepeval', action='store_true',
                           help='Run DeepEval on the database after evaluation')
    
    # Evaluate all command
    eval_all_parser = subparsers.add_parser('evaluate-all', help='Run evaluation with all models and baselines')
    eval_all_parser.add_argument('--database', default='database',
                               help='Database to use (database or database_leakagefree)')
    eval_all_parser.add_argument('--output-dir', default='results',
                               help='Directory to store output files')
    eval_all_parser.add_argument('--models-config', default=str(MODELS_CONFIG),
                               help='Path to models configuration file')
    eval_all_parser.add_argument('--tasks', nargs='*',
                               help='Specific tasks to run (default: all tasks)')
    eval_all_parser.add_argument('--no-scheduler', action='store_true',
                               help='Run without job scheduler (direct execution)')
    
    # Resume command
    resume_parser = subparsers.add_parser('resume', help='Resume a paused job')
    resume_parser.add_argument('job_id', help='Job ID to resume')
    resume_parser.add_argument('--output-dir', default='results',
                             help='Directory where job state is stored')
    
    # List jobs command
    list_parser = subparsers.add_parser('list-jobs', help='List all jobs')
    list_parser.add_argument('--output-dir', default='results',
                           help='Directory where job states are stored')
    list_parser.add_argument('--status', choices=['all', 'running', 'completed', 'failed', 'paused'],
                           default='all', help='Filter jobs by status')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check status of a specific job')
    status_parser.add_argument('job_id', help='Job ID to check')
    status_parser.add_argument('--output-dir', default='results',
                             help='Directory where job state is stored')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old completed jobs')
    cleanup_parser.add_argument('--days', type=int, default=30,
                              help='Delete completed jobs older than N days')
    cleanup_parser.add_argument('--output-dir', default='results',
                              help='Directory where job states are stored')
    
    # Models command
    models_parser = subparsers.add_parser('models', help='List available models')
    models_parser.add_argument('--config', default=str(MODELS_CONFIG),
                             help='Path to models configuration file')
    models_parser.add_argument('--type', choices=['all', 'llms', 'baselines'], default='all',
                             help='Type of models to list')
    
    # Auto-resume command
    auto_resume_parser = subparsers.add_parser('auto-resume', help='Automatically resume all incomplete jobs')
    auto_resume_parser.add_argument('--output-dir', default='results',
                                   help='Directory where job states are stored')
    auto_resume_parser.add_argument('--dry-run', action='store_true',
                                   help='Only show what would be resumed, don\'t actually resume')

    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Setup logging
    log_file = Path(args.output_dir if hasattr(args, 'output_dir') else 'output') / 'main.log'
    log_file.parent.mkdir(exist_ok=True, parents=True)
    logger = setup_logger("main", str(log_file), level=logging.INFO)
    
    try:
        if args.command == 'evaluate':
            handle_evaluate_command(args)
        elif args.command == 'evaluate-all':
            handle_evaluate_all_command(args)
        elif args.command == 'resume':
            handle_resume_command(args)
        elif args.command == 'list-jobs':
            handle_list_jobs_command(args)
        elif args.command == 'status':
            handle_status_command(args)
        elif args.command == 'cleanup':
            handle_cleanup_command(args)
        elif args.command == 'models':
            handle_models_command(args)
        elif args.command == 'auto-resume':
            handle_auto_resume_command(args)
    
    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)
        print(f"Error: {e}")
        sys.exit(1)

def handle_evaluate_command(args):
    """Handle the evaluate command."""
    # Load models config to validate model name
    models_config = load_models_config(args.models_config)
    
    all_models = {**models_config.get('llms', {}), **models_config.get('baselines', {})}
    if args.model not in all_models:
        available_models = list(all_models.keys())
        print(f"Error: Model '{args.model}' not found.")
        print(f"Available models: {', '.join(available_models)}")
        sys.exit(1)
    
    print(f"Starting evaluation with model: {args.model}")
    
    if args.both_databases:
        print("Running evaluation on both databases...")
        results = run_evaluation_on_both_databases(
            model_name=args.model,
            output_dir=args.output_dir,
            models_config_file=args.models_config,
            tasks=args.tasks,
            use_scheduler=not args.no_scheduler
        )
        
        print("Evaluation completed on both databases:")
        for db_name, job_state in results.items():
            if job_state:
                print(f"  {db_name}.sqlite: Job {job_state.job_id} - Status: {job_state.status}")
            else:
                print(f"  {db_name}.sqlite: Completed (direct execution)")
    else:
        print(f"Running evaluation on {args.database}.sqlite...")
        evaluator = AdvancedEvaluator(
            model_name=args.model,
            database_name=args.database,
            output_dir=args.output_dir,
            models_config_file=args.models_config,
            max_workers=args.max_workers
        )
        
        job_state = evaluator.run_evaluation(
            tasks=args.tasks,
            use_scheduler=not args.no_scheduler
        )
        
        if job_state:
            print(f"Job created: {job_state.job_id}")
            print(f"Status: {job_state.status}")
        else:
            print("Evaluation completed (direct execution)")

        # Optionally run DeepEval after evaluation
        if getattr(args, 'deepeval', False):
            try:
                from evaluation.deepeval_runner import run_deepeval
                db_name = f"{args.database}.sqlite" if not args.database.endswith('.sqlite') else args.database
                db_path = os.path.join(os.getcwd(), db_name)
                print(f"Running DeepEval on {db_path} ...")
                run_deepeval(db_path)
            except Exception as e:
                print(f"DeepEval failed: {e}")

def handle_evaluate_all_command(args):
    """Handle the evaluate-all command."""
    print(f"Running evaluation with all models on {args.database}.sqlite...")
    
    results = evaluate_all_models_and_baselines(
        output_dir=args.output_dir,
        models_config_file=args.models_config,
        database_name=args.database,
        tasks=args.tasks,
        use_scheduler=not args.no_scheduler
    )
    
    print("Evaluation completed for all models:")
    for model_name, job_state in results.items():
        if job_state:
            print(f"  {model_name}: Job {job_state.job_id} - Status: {job_state.status}")
        else:
            print(f"  {model_name}: Completed (direct execution)")

def handle_resume_command(args):
    """Handle the resume command."""
    scheduler = JobScheduler(
        state_dir=Path(args.output_dir) / "scheduler" / "state",
        log_dir=Path(args.output_dir) / "scheduler" / "logs"
    )
    
    job = scheduler.get_job_status(args.job_id)
    if not job:
        print(f"Job {args.job_id} not found")
        sys.exit(1)
    
    print(f"Resuming job {args.job_id}...")
    print(f"Model: {job.model_name}")
    print(f"Database: {job.database_name}")
    print(f"Current status: {job.status}")
    
    # Create evaluator and resume
    evaluator = AdvancedEvaluator(
        model_name=job.model_name,
        database_name=job.database_name,
        output_dir=args.output_dir
    )
    
    resumed_job = evaluator.run_evaluation(resume_job_id=args.job_id)
    print(f"Job resumed. Final status: {resumed_job.status}")

def handle_list_jobs_command(args):
    """Handle the list-jobs command."""
    scheduler = JobScheduler(
        state_dir=Path(args.output_dir) / "scheduler" / "state",
        log_dir=Path(args.output_dir) / "scheduler" / "logs"
    )
    
    jobs = scheduler.list_jobs()
    
    if args.status != 'all':
        jobs = [job for job in jobs if job.status == args.status]
    
    if not jobs:
        print("No jobs found")
        return
    
    print(f"Found {len(jobs)} jobs:")
    print(f"{'Job ID':<30} {'Model':<20} {'Database':<20} {'Status':<10} {'Progress'}")
    print("-" * 100)
    
    for job in jobs:
        progress = f"{len(job.completed_tasks)}/{len(job.progress)}" if job.progress else "N/A"
        print(f"{job.job_id:<30} {job.model_name:<20} {job.database_name:<20} {job.status:<10} {progress}")

def handle_status_command(args):
    """Handle the status command."""
    scheduler = JobScheduler(
        state_dir=Path(args.output_dir) / "scheduler" / "state",
        log_dir=Path(args.output_dir) / "scheduler" / "logs"
    )
    
    job = scheduler.get_job_status(args.job_id)
    if not job:
        print(f"Job {args.job_id} not found")
        sys.exit(1)
    
    print(f"Job Status: {args.job_id}")
    print(f"  Model: {job.model_name}")
    print(f"  Database: {job.database_name}")
    print(f"  Status: {job.status}")
    print(f"  Start Time: {job.start_time}")
    print(f"  Last Update: {job.last_update}")
    print(f"  Current Task: {job.current_task or 'None'}")
    print(f"  Current Commit: {job.current_commit_hash or 'None'}")
    print(f"  Completed Tasks: {job.completed_tasks}")
    print(f"  Progress: {job.progress}")
    
    if job.error_message:
        print(f"  Error: {job.error_message}")

def handle_cleanup_command(args):
    """Handle the cleanup command."""
    scheduler = JobScheduler(
        state_dir=Path(args.output_dir) / "scheduler" / "state",
        log_dir=Path(args.output_dir) / "scheduler" / "logs"
    )
    
    print(f"Cleaning up completed jobs older than {args.days} days...")
    scheduler.cleanup_completed_jobs(args.days)
    print("Cleanup completed")

def handle_models_command(args):
    """Handle the models command."""
    models_config = load_models_config(args.config)
    
    if args.type in ['all', 'llms']:
        llms = models_config.get('llms', {})
        if llms:
            print("Available LLMs:")
            for name, config in llms.items():
                category = config.get('category', 'unknown')
                description = config.get('description', 'No description')
                print(f"  {name:<25} ({category}) - {description}")
            print()
    
    if args.type in ['all', 'baselines']:
        baselines = models_config.get('baselines', {})
        if baselines:
            print("Available Baseline Models:")
            for name, config in baselines.items():
                dataset = config.get('dataset', 'unknown')
                description = config.get('description', 'No description')
                print(f"  {name:<25} ({dataset}) - {description}")

def handle_auto_resume_command(args):
    """Handle the auto-resume command."""
    scheduler = JobScheduler(
        state_dir=Path(args.output_dir) / "scheduler" / "state",
        log_dir=Path(args.output_dir) / "scheduler" / "logs"
    )
    
    print("=== VulnLLMEval Auto-Resume ===")
    print("Scanning for incomplete jobs...")
    
    incomplete_jobs = scheduler.check_and_resume_incomplete_jobs()
    
    if not incomplete_jobs:
        print("✓ No incomplete jobs found. All evaluations are up to date!")
        return
    
    print(f"Found {len(incomplete_jobs)} incomplete job(s):")
    for job in incomplete_jobs:
        print(f"  - {job.job_id} (model: {job.model_name}, database: {job.database_name}, status: {job.status})")
    
    if args.dry_run:
        print("\n[DRY RUN] Would resume the above jobs. Use without --dry-run to actually resume.")
        return
    
    print("\nResuming incomplete jobs...")
    
    resumed_count = 0
    failed_count = 0
    
    for job in incomplete_jobs:
        try:
            print(f"\nResuming job: {job.job_id}")
            
            # Create evaluator and resume
            evaluator = AdvancedEvaluator(
                model_name=job.model_name,
                database_name=job.database_name,
                output_dir=args.output_dir
            )
            
            resumed_job = evaluator.run_evaluation(resume_job_id=job.job_id)
            
            if resumed_job and resumed_job.status == "completed":
                print(f"✓ Job {job.job_id} completed successfully")
                resumed_count += 1
            else:
                print(f"⚠ Job {job.job_id} resumed but status: {resumed_job.status if resumed_job else 'unknown'}")
                
        except Exception as e:
            print(f"✗ Failed to resume job {job.job_id}: {e}")
            logger.error(f"Error resuming job {job.job_id}: {e}")
            failed_count += 1
    
    print(f"\n=== Auto-Resume Summary ===")
    print(f"Total jobs found: {len(incomplete_jobs)}")
    print(f"Successfully resumed: {resumed_count}")
    print(f"Failed to resume: {failed_count}")
    
    if failed_count > 0:
        print(f"\nFailed jobs can be resumed manually with:")
        print(f"  python main.py resume <job_id>")

if __name__ == "__main__":
    main()
