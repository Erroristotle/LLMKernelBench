"""
Download vulnerability detection datasets using Hugging Face datasets library.

This is an alternative to the manual download script that uses the Hugging Face
datasets library for easier access to hosted datasets.

Usage:
    python dataset/download_hf_datasets.py --all
    python dataset/download_hf_datasets.py --datasets devign
"""

import argparse
import logging
from pathlib import Path
from datasets import load_dataset
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HFDatasetDownloader:
    """Download datasets from Hugging Face."""

    DATASETS = {
        'devign': {
            'name': 'claudios/code_x_glue_devign',
            'description': 'Devign dataset for C/C++ vulnerability detection',
            'splits': ['train', 'validation', 'test']
        }
    }

    def __init__(self, output_dir: str = './data/benchmarks'):
        """Initialize the downloader.

        Args:
            output_dir: Directory to save datasets
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directory: {self.output_dir}")

    def download_devign(self) -> bool:
        """Download Devign dataset from Hugging Face.

        Returns:
            True if successful
        """
        logger.info("=" * 60)
        logger.info("Downloading Devign dataset from Hugging Face")
        logger.info("=" * 60)

        try:
            dataset_name = self.DATASETS['devign']['name']

            # Load all splits
            dataset = load_dataset(dataset_name)

            # Save each split as CSV
            for split in ['train', 'validation', 'test']:
                output_file = self.output_dir / f'devign_{split}.csv'

                if output_file.exists():
                    logger.info(f"Devign {split} already exists at {output_file}")
                    continue

                logger.info(f"Downloading Devign {split} split...")
                df = dataset[split].to_pandas()

                # Save to CSV
                df.to_csv(output_file, index=False)
                logger.info(f"Saved {len(df)} samples to {output_file}")

            # Also save a combined version
            combined_file = self.output_dir / 'devign_combined.csv'
            if not combined_file.exists():
                logger.info("Creating combined Devign dataset...")
                all_data = []
                for split in ['train', 'validation', 'test']:
                    df = dataset[split].to_pandas()
                    df['split'] = split
                    all_data.append(df)

                combined_df = pd.concat(all_data, ignore_index=True)
                combined_df.to_csv(combined_file, index=False)
                logger.info(f"Saved combined dataset: {len(combined_df)} samples")

            # Print statistics
            logger.info("\nDevign Dataset Statistics:")
            logger.info(f"  Train: {len(dataset['train'])} samples")
            logger.info(f"  Validation: {len(dataset['validation'])} samples")
            logger.info(f"  Test: {len(dataset['test'])} samples")

            # Check vulnerability distribution
            train_df = dataset['train'].to_pandas()
            vuln_count = train_df['target'].sum()
            clean_count = len(train_df) - vuln_count
            logger.info(f"  Vulnerable: {vuln_count}, Clean: {clean_count}")

            return True

        except Exception as e:
            logger.error(f"Error downloading Devign: {e}")
            return False

    def download_all(self) -> dict:
        """Download all available datasets.

        Returns:
            Dictionary with success status
        """
        results = {}
        results['devign'] = self.download_devign()

        # Summary
        logger.info("=" * 60)
        logger.info("Download Summary")
        logger.info("=" * 60)
        for dataset, success in results.items():
            status = "✓ SUCCESS" if success else "✗ FAILED"
            logger.info(f"{dataset.upper()}: {status}")

        return results


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Download vulnerability detection datasets from Hugging Face'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Download all available datasets'
    )

    parser.add_argument(
        '--datasets',
        nargs='+',
        choices=['devign'],
        help='Specific datasets to download'
    )

    parser.add_argument(
        '--output',
        default='./data/benchmarks',
        help='Output directory (default: ./data/benchmarks)'
    )

    args = parser.parse_args()

    downloader = HFDatasetDownloader(output_dir=args.output)

    if args.all or (args.datasets and 'devign' in args.datasets):
        results = downloader.download_all()
        if not all(results.values()):
            exit(1)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
