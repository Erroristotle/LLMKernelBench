"""
Download popular vulnerability detection benchmark datasets.

Datasets:
- Devign: Microsoft's vulnerability detection dataset (C/C++ functions)
- Reveal: CrossVul vulnerability detection dataset
- Big-Vul: Large-scale vulnerability dataset from real-world projects

Usage:
    python dataset/download_datasets.py --all
    python dataset/download_datasets.py --datasets devign reveal bigvul
    python dataset/download_datasets.py --output ./data/benchmarks
"""

import os
import argparse
import logging
import requests
import zipfile
import tarfile
import json
import pandas as pd
import gdown
from pathlib import Path
from typing import List, Optional
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatasetDownloader:
    """Download and prepare vulnerability detection benchmark datasets."""

    DATASETS = {
        'devign': {
            'name': 'Devign',
            'url': 'https://huggingface.co/datasets/claudios/code_x_glue_devign/resolve/main/data/train.jsonl',
            'description': 'Microsoft Devign dataset with 27k C/C++ functions',
            'file': 'devign_train.jsonl',
            'format': 'jsonl',
            'additional_urls': {
                'valid': 'https://huggingface.co/datasets/claudios/code_x_glue_devign/resolve/main/data/valid.jsonl',
                'test': 'https://huggingface.co/datasets/claudios/code_x_glue_devign/resolve/main/data/test.jsonl'
            }
        },
        'reveal': {
            'name': 'Reveal',
            'url': 'https://drive.google.com/uc?export=download&id=1Mn0jLaZWiPFQ8ejzlz_zXnx_TcSzbwu1',
            'description': 'Reveal GNN-based vulnerability detection dataset',
            'file': 'reveal_replication.zip',
            'format': 'zip',
            'gdrive_id': '1Mn0jLaZWiPFQ8ejzlz_zXnx_TcSzbwu1'
        },
        'bigvul': {
            'name': 'Big-Vul',
            'url': 'https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset/raw/master/all_c_cpp_release2.0.csv',
            'description': 'Large-scale C/C++ vulnerability dataset (MSR 2020) with 3,754 CVEs',
            'file': 'bigvul.csv',
            'format': 'csv',
            'alternative_url': 'https://raw.githubusercontent.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset/master/all_c_cpp_release2.0.csv'
        },
        'megavul': {
            'name': 'MegaVul',
            'url': 'https://github.com/Icyrockton/MegaVul/releases/download/v1.0/megavul_dataset_v1.tar.gz',
            'description': 'MegaVul - Largest high-quality C/C++/Java vulnerability dataset',
            'file': 'megavul_dataset_v1.tar.gz',
            'format': 'tar.gz',
            'github': 'https://github.com/Icyrockton/MegaVul'
        }
    }

    def __init__(self, output_dir: str = './data/benchmarks'):
        """Initialize the dataset downloader.

        Args:
            output_dir: Directory to save downloaded datasets
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directory: {self.output_dir}")

    def download_file(self, url: str, output_path: Path, chunk_size: int = 8192) -> bool:
        """Download a file with progress bar.

        Args:
            url: URL to download from
            output_path: Path to save the file
            chunk_size: Size of chunks to download

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Downloading from {url}")
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))

            with open(output_path, 'wb') as f, tqdm(
                desc=output_path.name,
                total=total_size,
                unit='B',
                unit_scale=True,
                unit_divisor=1024,
            ) as pbar:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))

            logger.info(f"Downloaded: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")
            return False

    def download_devign(self) -> bool:
        """Download the Devign dataset (train, valid, test splits).

        Returns:
            True if successful, False otherwise
        """
        logger.info("=" * 60)
        logger.info("Downloading Devign dataset")
        logger.info("=" * 60)

        dataset_info = self.DATASETS['devign']

        # Download train split
        output_path = self.output_dir / dataset_info['file']
        if not output_path.exists():
            success = self.download_file(dataset_info['url'], output_path)
            if not success:
                return False
        else:
            logger.info(f"Devign train split already exists")

        # Download additional splits
        all_success = True
        if 'additional_urls' in dataset_info:
            for split_name, split_url in dataset_info['additional_urls'].items():
                split_file = self.output_dir / f"devign_{split_name}.jsonl"
                if not split_file.exists():
                    success = self.download_file(split_url, split_file)
                    if not success:
                        all_success = False
                else:
                    logger.info(f"Devign {split_name} split already exists")

        if all_success:
            # Validate the JSONL files
            try:
                with open(output_path, 'r') as f:
                    lines = f.readlines()
                    sample = json.loads(lines[0])
                logger.info(f"Devign train dataset: {len(lines)} samples")
                logger.info(f"Sample keys: {list(sample.keys())}")
            except Exception as e:
                logger.error(f"Error validating Devign dataset: {e}")
                return False

        return all_success

    def download_reveal(self) -> bool:
        """Download the Reveal dataset from Google Drive.

        Returns:
            True if successful, False otherwise
        """
        logger.info("=" * 60)
        logger.info("Downloading Reveal dataset from Google Drive")
        logger.info("=" * 60)

        dataset_info = self.DATASETS['reveal']
        output_path = self.output_dir / dataset_info['file']

        # Check if already extracted
        extracted_dir = self.output_dir / 'reveal'
        if extracted_dir.exists():
            logger.info(f"Reveal dataset already extracted at {extracted_dir}")
            return True

        if output_path.exists():
            logger.info(f"Reveal zip already exists at {output_path}")
        else:
            # Download from Google Drive using gdown
            try:
                logger.info(f"Downloading from Google Drive (ID: {dataset_info['gdrive_id']})...")
                gdown.download(id=dataset_info['gdrive_id'], output=str(output_path), quiet=False)
            except Exception as e:
                logger.error(f"Error downloading Reveal dataset: {e}")
                return False

        # Extract the zip file
        try:
            logger.info("Extracting Reveal dataset...")
            with zipfile.ZipFile(output_path, 'r') as zip_ref:
                zip_ref.extractall(self.output_dir / 'reveal')
            logger.info("Reveal dataset extracted successfully")

            # List extracted files
            extracted_files = list((self.output_dir / 'reveal').rglob('*'))
            csv_files = [f for f in extracted_files if f.suffix == '.csv']
            logger.info(f"Extracted {len(extracted_files)} files, including {len(csv_files)} CSV files")

            # Try to find and validate a main CSV file
            if csv_files:
                sample_csv = csv_files[0]
                df = pd.read_csv(sample_csv)
                logger.info(f"Sample CSV ({sample_csv.name}): {len(df)} samples")

            return True

        except Exception as e:
            logger.error(f"Error extracting Reveal dataset: {e}")
            return False

    def download_bigvul(self) -> bool:
        """Download the Big-Vul dataset.

        Returns:
            True if successful, False otherwise
        """
        logger.info("=" * 60)
        logger.info("Downloading Big-Vul dataset")
        logger.info("=" * 60)

        dataset_info = self.DATASETS['bigvul']
        output_path = self.output_dir / dataset_info['file']

        if output_path.exists():
            logger.info(f"Big-Vul dataset already exists at {output_path}")
            return True

        success = self.download_file(dataset_info['url'], output_path)

        if success:
            # Validate the CSV file
            try:
                df = pd.read_csv(output_path)
                logger.info(f"Big-Vul dataset: {len(df)} samples")
                logger.info(f"Columns: {list(df.columns)}")
                if 'target' in df.columns:
                    logger.info(f"Vulnerable: {df['target'].sum()}, Clean: {(df['target']==0).sum()}")
            except Exception as e:
                logger.error(f"Error validating Big-Vul dataset: {e}")
                return False

        return success

    def download_megavul(self) -> bool:
        """Download the MegaVul dataset.

        Returns:
            True if successful, False otherwise
        """
        logger.info("=" * 60)
        logger.info("Downloading MegaVul dataset")
        logger.info("=" * 60)

        dataset_info = self.DATASETS['megavul']
        output_path = self.output_dir / dataset_info['file']

        if output_path.exists():
            logger.info(f"MegaVul dataset already exists at {output_path}")
            # Check if already extracted
            extracted_dir = self.output_dir / 'megavul'
            if extracted_dir.exists():
                logger.info("MegaVul dataset already extracted")
                return True

        success = self.download_file(dataset_info['url'], output_path)

        if success:
            # Extract the tar.gz file
            try:
                logger.info("Extracting MegaVul dataset...")
                with tarfile.open(output_path, 'r:gz') as tar:
                    tar.extractall(path=self.output_dir)
                logger.info("MegaVul dataset extracted successfully")

                # Validate
                extracted_dir = self.output_dir / 'megavul'
                if extracted_dir.exists():
                    files = list(extracted_dir.glob('*'))
                    logger.info(f"MegaVul extracted: {len(files)} files/directories")
                else:
                    logger.warning("MegaVul extraction directory not found")

            except Exception as e:
                logger.error(f"Error extracting MegaVul dataset: {e}")
                return False

        return success

    def download_all(self) -> dict:
        """Download all available datasets.

        Returns:
            Dictionary with dataset names and success status
        """
        results = {}

        logger.info("Starting download of all datasets...")

        results['devign'] = self.download_devign()
        results['reveal'] = self.download_reveal()
        results['bigvul'] = self.download_bigvul()
        results['megavul'] = self.download_megavul()

        # Summary
        logger.info("=" * 60)
        logger.info("Download Summary")
        logger.info("=" * 60)
        for dataset, success in results.items():
            status = "✓ SUCCESS" if success else "✗ FAILED"
            logger.info(f"{dataset.upper()}: {status}")

        return results

    def download_specific(self, datasets: List[str]) -> dict:
        """Download specific datasets.

        Args:
            datasets: List of dataset names to download

        Returns:
            Dictionary with dataset names and success status
        """
        results = {}

        for dataset in datasets:
            dataset = dataset.lower()
            if dataset not in self.DATASETS:
                logger.error(f"Unknown dataset: {dataset}")
                logger.info(f"Available datasets: {', '.join(self.DATASETS.keys())}")
                results[dataset] = False
                continue

            if dataset == 'devign':
                results[dataset] = self.download_devign()
            elif dataset == 'reveal':
                results[dataset] = self.download_reveal()
            elif dataset == 'bigvul':
                results[dataset] = self.download_bigvul()
            elif dataset == 'megavul':
                results[dataset] = self.download_megavul()

        return results

    def list_datasets(self):
        """List all available datasets with descriptions."""
        logger.info("=" * 60)
        logger.info("Available Datasets")
        logger.info("=" * 60)

        for key, info in self.DATASETS.items():
            logger.info(f"\n{key.upper()}:")
            logger.info(f"  Name: {info['name']}")
            logger.info(f"  Description: {info['description']}")
            logger.info(f"  Format: {info['format']}")
            logger.info(f"  Output: {info['file']}")


def main():
    """Main function to run the dataset downloader."""
    parser = argparse.ArgumentParser(
        description='Download vulnerability detection benchmark datasets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download all datasets
  python dataset/download_datasets.py --all

  # Download specific datasets
  python dataset/download_datasets.py --datasets devign reveal

  # Download MegaVul only (large dataset ~1.5GB)
  python dataset/download_datasets.py --datasets megavul

  # Specify custom output directory
  python dataset/download_datasets.py --all --output ./data/my_benchmarks

  # List available datasets
  python dataset/download_datasets.py --list
        """
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Download all available datasets'
    )

    parser.add_argument(
        '--datasets',
        nargs='+',
        help='Specific datasets to download (devign, reveal, bigvul, megavul)'
    )

    parser.add_argument(
        '--output',
        default='./data/benchmarks',
        help='Output directory for datasets (default: ./data/benchmarks)'
    )

    parser.add_argument(
        '--list',
        action='store_true',
        help='List all available datasets'
    )

    args = parser.parse_args()

    downloader = DatasetDownloader(output_dir=args.output)

    if args.list:
        downloader.list_datasets()
        return

    if args.all:
        results = downloader.download_all()
    elif args.datasets:
        results = downloader.download_specific(args.datasets)
    else:
        parser.print_help()
        return

    # Exit with error code if any download failed
    if not all(results.values()):
        logger.error("Some downloads failed!")
        exit(1)
    else:
        logger.info("All downloads completed successfully!")


if __name__ == '__main__':
    main()
