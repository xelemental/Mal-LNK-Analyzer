# Mal-LNK-Analyzer
# LNK File Analyzer

A cross-platform tool to parse Windows LNK (shortcut) files and analyze them for malicious indicators. This tool extracts important artifacts from LNK files and can check them against VirusTotal to identify potentially malicious shortcuts.


## Features

- **Comprehensive LNK Parsing**: Extracts critical artifacts including target path, machine ID, MAC address, and command line arguments
- **Hash Calculation**: Generates MD5, SHA1, and SHA256 hashes of LNK files
- **VirusTotal Integration**: Checks files against VirusTotal's database and displays detection results
- **Upload Capability**: Can upload new files to VirusTotal and wait for analysis results
- **Cross-Platform**: Works on both Windows and Linux
- **Colorized Output**: Easy-to-read color-coded console output
- **JSON Export**: Option to save analysis results as JSON for further processing

## Screenshot

![image](https://github.com/user-attachments/assets/088ecd17-f590-45a1-a40e-93bd3880ce7b)


## Installation

### Prerequisites

- Python 3.6+
- pip (Python package manager)

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/lnk-analyzer.git
   cd lnk-analyzer
   ```

2. Install the required dependencies:
   ```bash
   pip install pylnk3 requests colorama
   ```

3. Make the script executable (Linux/macOS):
   ```bash
   chmod +x lnk_analyzer.py
   ```

## Usage

Basic usage:
```bash
python lnk_analyzer.py path/to/file.lnk
```

With VirusTotal check:
```bash
python lnk_analyzer.py path/to/file.lnk --api-key YOUR_VT_API_KEY
```

Upload to VirusTotal if not found:
```bash
python lnk_analyzer.py path/to/file.lnk --api-key YOUR_VT_API_KEY --upload
```

Save results to a JSON file:
```bash
python lnk_analyzer.py path/to/file.lnk --api-key YOUR_VT_API_KEY --output results.json
```

### Command Line Options

```
usage: lnk_analyzer.py [-h] [--api-key API_KEY] [--upload] [--output OUTPUT] lnk_file

LNK File Analyzer - Extract artifacts and check against VirusTotal

positional arguments:
  lnk_file              Path to the LNK file to analyze

optional arguments:
  -h, --help            show this help message and exit
  --api-key API_KEY     VirusTotal API key
  --upload              Upload file to VirusTotal if not already present
  --output OUTPUT       Save results to specified JSON file
```

## Example Output

![image](https://github.com/user-attachments/assets/831dbef7-f7a3-470a-b3b0-8c0397f2403b)


## Analysis Details

The tool extracts the following information from LNK files:

### File Information
- Filename
- File size
- MD5, SHA1, and SHA256 hashes

### Target Information
- Target path
- Target relative path
- Working directory
- Command line arguments

### Machine Information
- Machine ID
- MAC Address (when available)
- Droid Volume ID
- Droid File ID

### Timestamps
- Creation time
- Modification time
- Access time

### VirusTotal Results (when API key is provided)
- Detection ratio
- Scan date
- Permalink to full results

## Use Cases

- **Malware Analysis**: Quickly analyze suspicious LNK files for malicious indicators
- **Forensic Investigation**: Extract important metadata from LNK files during digital forensics
- **Security Operations**: Automate LNK file analysis in security operations workflows
- **Incident Response**: Rapidly assess the threat level of suspicious shortcuts during incidents

## Advanced Usage

### Environment Variables

You can set your VirusTotal API key as an environment variable instead of passing it each time:

```bash
export VT_API_KEY=your_api_key_here
python lnk_analyzer.py path/to/file.lnk
```

### Batch Processing

To analyze multiple LNK files, you can use a simple shell loop:

```bash
for file in *.lnk; do
  python lnk_analyzer.py "$file" --output "${file%.lnk}_analysis.json"
done
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [pylnk3](https://github.com/strayge/pylnk) for the LNK parsing capabilities
- [VirusTotal](https://www.virustotal.com/) for providing the API to check files
- [colorama](https://github.com/tartley/colorama) for cross-platform colored terminal output

## Contact

For questions or feedback, please open an issue on this repository.
