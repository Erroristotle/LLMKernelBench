"""Setup script for VulnLLMEval package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vulnllmeval",
    version="2.0.0",
    author="VulnLLMEval Team",
    author_email="your.email@example.com",
    description="Advanced framework for evaluating LLMs on vulnerability detection and repair",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vulnllmeval",
    packages=find_packages(exclude=["tests*", "linux*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vulnllmeval=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.md", "*.txt"],
    },
) 