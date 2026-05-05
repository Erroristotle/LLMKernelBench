"""
Load and adapt benchmark vulnerability detection datasets.

This module provides a unified interface to load popular benchmark datasets
(Devign, Big-Vul, Reveal) and convert them to the project's database format.

Usage:
    from dataset.benchmark_loader import BenchmarkLoader

    loader = BenchmarkLoader('./data/benchmarks')

    # Load Devign dataset
    devign_data = loader.load_devign(split='train')

    # Load Big-Vul dataset
    bigvul_data = loader.load_bigvul()

    # Convert to project database format
    converted = loader.convert_to_db_format(devign_data, source='devign')
"""

import pandas as pd
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BenchmarkLoader:
    """Load and convert benchmark vulnerability detection datasets."""

    def __init__(self, benchmarks_dir: str = './data/benchmarks'):
        """Initialize the benchmark loader.

        Args:
            benchmarks_dir: Directory containing benchmark datasets
        """
        self.benchmarks_dir = Path(benchmarks_dir)
        if not self.benchmarks_dir.exists():
            raise FileNotFoundError(f"Benchmarks directory not found: {benchmarks_dir}")

        logger.info(f"Initialized BenchmarkLoader with directory: {self.benchmarks_dir}")

    def load_devign(self, split: str = 'train') -> pd.DataFrame:
        """Load Devign dataset.

        Args:
            split: Dataset split ('train', 'validation', 'test', or 'combined')

        Returns:
            DataFrame with Devign data
        """
        file_path = self.benchmarks_dir / f'devign_{split}.csv'

        if not file_path.exists():
            raise FileNotFoundError(f"Devign {split} split not found at {file_path}")

        logger.info(f"Loading Devign {split} split from {file_path}")
        df = pd.read_csv(file_path)

        logger.info(f"Loaded {len(df)} samples from Devign {split}")
        logger.info(f"Columns: {list(df.columns)}")

        return df

    def load_bigvul(self) -> pd.DataFrame:
        """Load Big-Vul dataset.

        Returns:
            DataFrame with Big-Vul data
        """
        file_path = self.benchmarks_dir / 'bigvul.csv'

        if not file_path.exists():
            raise FileNotFoundError(f"Big-Vul dataset not found at {file_path}")

        logger.info(f"Loading Big-Vul dataset from {file_path}")
        df = pd.read_csv(file_path)

        logger.info(f"Loaded {len(df)} samples from Big-Vul")
        logger.info(f"Columns: {list(df.columns)}")

        return df

    def get_dataset_stats(self, dataset_name: str) -> Dict:
        """Get statistics about a dataset.

        Args:
            dataset_name: Name of the dataset ('devign' or 'bigvul')

        Returns:
            Dictionary with dataset statistics
        """
        stats = {}

        if dataset_name.lower() == 'devign':
            # Load all splits
            for split in ['train', 'validation', 'test']:
                try:
                    df = self.load_devign(split)
                    stats[split] = {
                        'total': len(df),
                        'vulnerable': int(df['target'].sum()) if 'target' in df.columns else 0,
                        'clean': int((df['target'] == 0).sum()) if 'target' in df.columns else 0
                    }
                except FileNotFoundError:
                    pass

        elif dataset_name.lower() == 'bigvul':
            df = self.load_bigvul()

            # Big-Vul doesn't have a standard 'target' column, need to check column names
            # Typically vulnerability info is in various columns
            stats['all'] = {
                'total': len(df),
                'columns': list(df.columns),
                'cve_count': df['cve_id'].nunique() if 'cve_id' in df.columns else 0
            }

        return stats

    def convert_devign_to_db_format(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert Devign dataset to project database format.

        Args:
            df: Devign DataFrame

        Returns:
            DataFrame in database format
        """
        logger.info("Converting Devign to database format...")

        converted = pd.DataFrame()

        # Map Devign columns to database columns
        converted['COMMIT_HASH'] = df['commit_id'] if 'commit_id' in df.columns else df['id'].astype(str)
        converted['VULNERABILITY_CVE'] = 'DEVIGN-' + df['id'].astype(str)  # Synthetic CVE IDs
        converted['VULNERABILITY_YEAR'] = None  # Not available in Devign
        converted['VULNERABILITY_CWE'] = None  # Not available in Devign
        converted['VULNERABILITY_CATEGORY'] = None
        converted['REPO_URL'] = df['project'] if 'project' in df.columns else None
        converted['DESCRIPTION_IN_PATCH'] = 'Devign benchmark sample'
        converted['VULNERABLE_CODE_BLOCK'] = df['func'] if 'func' in df.columns else ''
        converted['PATCHED_CODE_BLOCK'] = None  # Not available
        converted['NUM_FILES_CHANGED'] = None
        converted['NUM_FUNCTIONS_CHANGED'] = 1
        converted['NUM_LINES_ADDED'] = None
        converted['NUM_LINES_DELETED'] = None
        converted['TARGET_LABEL'] = df['target'] if 'target' in df.columns else 0

        logger.info(f"Converted {len(converted)} Devign samples to database format")

        return converted

    def convert_bigvul_to_db_format(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert Big-Vul dataset to project database format.

        Args:
            df: Big-Vul DataFrame

        Returns:
            DataFrame in database format
        """
        logger.info("Converting Big-Vul to database format...")

        converted = pd.DataFrame()

        # Map Big-Vul columns to database columns
        converted['COMMIT_HASH'] = df['commit_id'] if 'commit_id' in df.columns else None
        converted['VULNERABILITY_CVE'] = df['cve_id'] if 'cve_id' in df.columns else None
        converted['VULNERABILITY_YEAR'] = df['publish_date'].str[:4] if 'publish_date' in df.columns else None
        converted['VULNERABILITY_CWE'] = df['cwe_id'] if 'cwe_id' in df.columns else None
        converted['VULNERABILITY_CATEGORY'] = df['vulnerability_classification'] if 'vulnerability_classification' in df.columns else None
        converted['REPO_URL'] = df['project'] if 'project' in df.columns else None
        converted['DESCRIPTION_IN_PATCH'] = df['commit_message'] if 'commit_message' in df.columns else df['summary'] if 'summary' in df.columns else None
        converted['VULNERABLE_CODE_BLOCK'] = None  # Would need to extract from diffs
        converted['PATCHED_CODE_BLOCK'] = None
        converted['NUM_FILES_CHANGED'] = df['files_changed'] if 'files_changed' in df.columns else None
        converted['NUM_FUNCTIONS_CHANGED'] = None
        converted['NUM_LINES_ADDED'] = None
        converted['NUM_LINES_DELETED'] = None

        logger.info(f"Converted {len(converted)} Big-Vul samples to database format")

        return converted

    def export_to_csv(self, df: pd.DataFrame, output_path: str) -> None:
        """Export DataFrame to CSV format.

        Args:
            df: DataFrame to export
            output_path: Output file path
        """
        df.to_csv(output_path, index=False)
        logger.info(f"Exported {len(df)} samples to {output_path}")

    def get_sample_data(self, dataset_name: str, n: int = 5) -> pd.DataFrame:
        """Get sample data from a dataset.

        Args:
            dataset_name: Name of the dataset
            n: Number of samples to return

        Returns:
            DataFrame with sample data
        """
        if dataset_name.lower() == 'devign':
            df = self.load_devign('train')
        elif dataset_name.lower() == 'bigvul':
            df = self.load_bigvul()
        else:
            raise ValueError(f"Unknown dataset: {dataset_name}")

        return df.head(n)


def main():
    """Example usage of BenchmarkLoader."""
    loader = BenchmarkLoader('./data/benchmarks')

    # Get statistics
    print("\n" + "=" * 60)
    print("Dataset Statistics")
    print("=" * 60)

    print("\nDevign:")
    devign_stats = loader.get_dataset_stats('devign')
    for split, stats in devign_stats.items():
        print(f"  {split}:")
        print(f"    Total: {stats['total']}")
        print(f"    Vulnerable: {stats['vulnerable']}")
        print(f"    Clean: {stats['clean']}")

    print("\nBig-Vul:")
    bigvul_stats = loader.get_dataset_stats('bigvul')
    for split, stats in bigvul_stats.items():
        print(f"  {split}:")
        print(f"    Total: {stats['total']}")
        if 'cve_count' in stats:
            print(f"    Unique CVEs: {stats['cve_count']}")

    # Load and convert sample data
    print("\n" + "=" * 60)
    print("Sample Data Conversion")
    print("=" * 60)

    print("\nLoading Devign train split...")
    devign_train = loader.load_devign('train')
    devign_converted = loader.convert_devign_to_db_format(devign_train.head(10))
    print(f"\nConverted columns: {list(devign_converted.columns)}")

    print("\nLoading Big-Vul...")
    bigvul = loader.load_bigvul()
    bigvul_converted = loader.convert_bigvul_to_db_format(bigvul.head(10))
    print(f"\nConverted columns: {list(bigvul_converted.columns)}")


if __name__ == '__main__':
    main()
