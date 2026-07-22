"""
Setup configuration for Attack Thinking Engine (ATE).
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="attack-thinking-engine",
    version="0.1.0",
    author="Security Research Team",
    author_email="research@example.com",
    description="Automated Attack Path Analysis Engine - Graph-based vulnerability chain analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/Omotenet-ATE",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ate=ate.cli.main:cli",
        ],
    },
    include_package_data=True,
    keywords="security vulnerability analysis attack-path graph networkx penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/Omotenet-ATE/issues",
        "Source": "https://github.com/yourusername/Omotenet-ATE",
        "Documentation": "https://github.com/yourusername/Omotenet-ATE/wiki",
    },
)
