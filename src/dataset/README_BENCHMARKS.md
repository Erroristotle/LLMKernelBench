# Benchmark Vulnerability Detection Datasets

This directory contains tools to download, process, and use popular vulnerability detection benchmark datasets for evaluating LLM and baseline models.

## 📊 Available Datasets

### Successfully Downloaded

| Dataset | Samples | Description | Status |
|---------|---------|-------------|--------|
| **Devign** | 27,318 | Microsoft's C/C++ vulnerability detection dataset from FFmpeg and Qemu projects | ✅ Downloaded |
| **Big-Vul** | 4,432 | Large-scale C/C++ vulnerability dataset from MSR 2020 with 3,754 unique CVEs | ✅ Downloaded |
| **MegaVul** | ~1M+ | Largest C/C++/Java vulnerability dataset (requires manual download) | ⚠️ Manual |
| **Reveal** | - | GNN-based vulnerability detection dataset | ⚠️ Access restricted |

### Dataset Details

#### Devign
- **Paper**: "Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks" (NeurIPS 2019)
- **Source**: Microsoft Research
- **Content**: Function-level C/C++ code snippets
- **Splits**: Train (21,854), Validation (2,732), Test (2,732)
- **Balance**: ~46% vulnerable, ~54% clean
- **Projects**: FFmpeg, Qemu

#### Big-Vul
- **Paper**: "A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries" (MSR 2020)
- **Source**: GitHub repositories
- **Content**: Commit-level changes with CVE information
- **Features**: 22 columns including CVE ID, CWE ID, commit messages, CVSS scores
- **Years Covered**: 2002-2019
- **Vulnerability Types**: 91 different types

#### MegaVul (Manual Download)
- **Paper**: "MegaVul: A C/C++ Vulnerability Dataset with Comprehensive Code Representations" (2024)
- **Source**: https://github.com/Icyrockton/MegaVul
- **Content**: Largest vulnerability dataset with multiple code representations
- **Size**: ~1.5GB compressed
- **Note**: Download link requires GitHub release access

#### Reveal (Access Restricted)
- **Paper**: "Deep Learning Based Vulnerability Detection: Are We There Yet?" (TSE 2021)
- **Source**: https://github.com/VulDetProject/ReVeal
- **Content**: Devign + Chrome/Debian projects
- **Note**: Original Google Drive link has restricted access
- **Alternative**: Use DiverseVul merged dataset (see below)

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install pandas requests tqdm datasets gdown
```

Or install all project requirements:
```bash
pip install -r requirements.txt
pip install datasets gdown  # Additional dependencies
```

### 2. Download Datasets

#### Download All Available Datasets
```bash
python dataset/download_datasets.py --all
```

#### Download Specific Datasets
```bash
# Download Devign only
python dataset/download_hf_datasets.py --datasets devign

# Download Big-Vul only
python dataset/download_datasets.py --datasets bigvul

# Download multiple
python dataset/download_datasets.py --datasets devign bigvul
```

#### Custom Output Directory
```bash
python dataset/download_datasets.py --all --output ./my_datasets
```

### 3. List Available Datasets
```bash
python dataset/download_datasets.py --list
```

## 📁 Directory Structure

After downloading, your directory will look like:

```
data/benchmarks/
├── devign_train.csv           # Devign training set (21,854 samples)
├── devign_validation.csv      # Devign validation set (2,732 samples)
├── devign_test.csv           # Devign test set (2,732 samples)
├── devign_combined.csv       # All Devign splits combined (27,318 samples)
├── bigvul.csv               # Big-Vul dataset (4,432 samples)
└── README.md                # This file
```

## 🔧 Using the Benchmark Loader

The `benchmark_loader.py` module provides a unified interface to load and convert benchmark datasets.

### Basic Usage

```python
from dataset.benchmark_loader import BenchmarkLoader

# Initialize loader
loader = BenchmarkLoader('./data/benchmarks')

# Load Devign dataset
devign_train = loader.load_devign(split='train')
devign_test = loader.load_devign(split='test')
devign_all = loader.load_devign(split='combined')

# Load Big-Vul dataset
bigvul = loader.load_bigvul()

# Get dataset statistics
devign_stats = loader.get_dataset_stats('devign')
bigvul_stats = loader.get_dataset_stats('bigvul')

# Get sample data
samples = loader.get_sample_data('devign', n=10)
```

### Convert to Database Format

```python
# Convert Devign to project database format
devign_converted = loader.convert_devign_to_db_format(devign_train)

# Convert Big-Vul to project database format
bigvul_converted = loader.convert_bigvul_to_db_format(bigvul)

# Export to CSV
loader.export_to_csv(devign_converted, 'devign_db_format.csv')
```

### Integration with Main Evaluation Pipeline

```python
# Example: Use Devign for additional evaluation
from dataset.benchmark_loader import BenchmarkLoader
from models.llm_manager import LLMManager

loader = BenchmarkLoader('./data/benchmarks')
devign_test = loader.load_devign('test')

# Evaluate on Devign test set
llm = LLMManager(model_name='gemini')
for idx, row in devign_test.iterrows():
    code = row['func']
    label = row['target']
    # Run evaluation...
```

## 📊 Dataset Statistics

### Devign

| Split | Total | Vulnerable | Clean |
|-------|-------|------------|-------|
| Train | 21,854 | 10,018 (45.8%) | 11,836 (54.2%) |
| Validation | 2,732 | 1,187 (43.4%) | 1,545 (56.6%) |
| Test | 2,732 | 1,255 (45.9%) | 1,477 (54.1%) |
| **Total** | **27,318** | **12,460 (45.6%)** | **14,858 (54.4%)** |

### Big-Vul

- **Total Samples**: 4,432
- **Unique CVEs**: 3,754
- **Time Period**: 2002-2019
- **Vulnerability Types**: 91 different CWE classifications
- **Programming Language**: C/C++

### Dataset Columns

#### Devign Columns
- `id`: Sample identifier
- `func`: Function source code
- `target`: Vulnerability label (1=vulnerable, 0=clean)
- `project`: Project name (FFmpeg or Qemu)
- `commit_id`: Git commit hash

#### Big-Vul Columns (22 total)
- `cve_id`: CVE identifier
- `cwe_id`: CWE classification
- `commit_id`: Git commit hash
- `commit_message`: Commit description
- `project`: Repository name
- `files_changed`: Number of files modified
- `publish_date`: CVE publication date
- `score`: CVSS score
- `summary`: Vulnerability description
- `vulnerability_classification`: Type of vulnerability
- And 12 more metadata fields

## 🔄 Alternative Datasets

### DiverseVul (Merged Dataset)

If you need access to Reveal or want a merged dataset, consider **DiverseVul** which combines multiple benchmark datasets:

- **GitHub**: https://github.com/wagner-group/diversevul
- **Paper**: "DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection" (RAID 2023)
- **Contents**: Merges Devign, ReVeal, BigVul, CrossVul, and CVEfixes
- **Download**: https://drive.google.com/drive/folders/1BeX33sgLOWLBnJ_vjcYitzz87F1kFZWi

### MegaVul (Manual Download)

For the largest available dataset:

1. Visit: https://github.com/Icyrockton/MegaVul
2. Go to Releases
3. Download `megavul_dataset_v1.tar.gz` (~1.5GB)
4. Extract to `data/benchmarks/megavul/`

Or use the download script (if release is public):
```bash
python dataset/download_datasets.py --datasets megavul
```

## 📝 Citation

If you use these datasets in your research, please cite the original papers:

### Devign
```bibtex
@inproceedings{zhou2019devign,
  title={Devign: Effective vulnerability identification by learning comprehensive program semantics via graph neural networks},
  author={Zhou, Yaqin and Liu, Shangqing and Siow, Jingkai and Du, Xiaoning and Liu, Yang},
  booktitle={NeurIPS},
  year={2019}
}
```

### Big-Vul
```bibtex
@inproceedings{fan2020ac,
  title={A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries},
  author={Fan, Jiahao and Li, Yi and Wang, Shaohua and Nguyen, Tien N},
  booktitle={MSR},
  year={2020}
}
```

### MegaVul
```bibtex
@article{zhang2024megavul,
  title={MegaVul: A C/C++ Vulnerability Dataset with Comprehensive Code Representations},
  author={Zhang, Xin and others},
  journal={arXiv preprint arXiv:2406.12415},
  year={2024}
}
```

## 🛠️ Troubleshooting

### Issue: Dataset Download Fails

**Solution**: Check your internet connection and try again. For Google Drive downloads, the file may have access restrictions.

### Issue: "File not found" Error

**Solution**: Ensure you've run the download script first:
```bash
python dataset/download_datasets.py --all
```

### Issue: Reveal Dataset Not Downloading

**Solution**: The original Google Drive link has restricted access. Consider:
1. Using the DiverseVul merged dataset
2. Contacting the ReVeal authors directly
3. Using only Devign and Big-Vul for evaluation

### Issue: Memory Error Loading Large Datasets

**Solution**: Load datasets in chunks or filter specific columns:
```python
# Load only specific columns
devign = pd.read_csv('devign_train.csv', usecols=['func', 'target'])

# Load in chunks
for chunk in pd.read_csv('bigvul.csv', chunksize=1000):
    process(chunk)
```

## 📧 Support

For issues with:
- **Download scripts**: Open an issue in this repository
- **Dataset content**: Contact the original dataset authors
- **Integration**: Check the main project README or open an issue

## 🔗 Useful Links

- [Devign GitHub](https://github.com/epicosy/devign)
- [Big-Vul GitHub](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset)
- [MegaVul GitHub](https://github.com/Icyrockton/MegaVul)
- [DiverseVul GitHub](https://github.com/wagner-group/diversevul)
- [ReVeal GitHub](https://github.com/VulDetProject/ReVeal)
- [Hugging Face Datasets](https://huggingface.co/docs/datasets)

---

**Last Updated**: November 2024
**Status**: Devign ✅ | Big-Vul ✅ | MegaVul ⚠️ Manual | Reveal ⚠️ Restricted
