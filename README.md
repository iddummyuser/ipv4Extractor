# IPv4 Address Extractor

A robust Python tool for extracting IPv4 addresses and subnets from multiple files, with support for automatic subnet expansion and invalid entry recovery.

## Features

- ✨ Extracts IPv4 addresses and subnets from multiple files
- 🔍 Automatically detects and handles different file encodings
- 🌐 Expands IPv4 subnets with user confirmation or automatic mode
- 🔄 Recovers valid IPv4 addresses from invalid entries
- 📊 Provides detailed progress bars and statistics
- 📝 Generates comprehensive error logs
- 🚫 Skips IPv6 addresses and invalid entries
- 🎯 Sorts and deduplicates IP addresses
- 💡 Handles large subnets with batch processing

## Requirements

- Python 3.7+
- Required packages:
  ```bash
  pip install click rich tqdm chardet

##  Installation

Clone the repository or download the source files:
```bash
bashCopygit clone https://github.com/yourusername/ipv4-extractor.git
cd ipv4-extractor
```

## Install dependencies:
```bash
bashCopypip install -r requirements.txt
```

## Usage
### Basic Usage
```bash
bashCopypython ip_extractor.py <folder_path> <output_file>
```
### Advanced Usage
```bash
bashCopypython ip_extractor.py <folder_path> <output_file> [OPTIONS]
```
### Options

--expand-all, -e: Automatically expand all subnets without prompting
--no-progress, -np: Disable progress bars
--quiet, -q: Suppress non-error output
