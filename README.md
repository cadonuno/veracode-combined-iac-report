# Veracode Combined IaC Report

A Python script that combines Infrastructure-as-Code (IaC) scan results from multiple git repositories using the Veracode CLI into a single Excel report.

## Features

- Scans multiple git repositories for vulnerabilities, secrets, and misconfigurations
- Combines results from all repositories into a single Excel file
- Separate tabs for vulnerabilities, secrets, and configuration issues
- Detailed formatting of CVE information and available fixes
- Structured data export with raw JSON for additional analysis

## Requirements

- Python 3.11+
- [Veracode CLI](https://docs.veracode.com/r/Veracode_CLI) installed and configured

## Installation

1. Install Veracode CLI following the [official documentation](https://docs.veracode.com/r/Install_the_Veracode_CLI)

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Run the script:
1. The script will prompt you to enter git URLs one at a time. Press Enter without typing a URL to finish the list.
2. The script will then prompt you for a file name to save (defaults to 'combined_iac_report.xlsx')

### The script will:

1. Run Veracode scans on each repository
2. Process and aggregate the results
3. Export all findings to combined_iac_report.xlsx

### Output:
The generated Excel report contains three sheets:

 - vulnerabilities: Component vulnerabilities with CVE details and available fixes
 - secrets: Discovered secrets with severity and location information
 - configs: Configuration issues found in the repositories