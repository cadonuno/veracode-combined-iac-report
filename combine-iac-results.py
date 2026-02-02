import subprocess
import json
from openpyxl import Workbook
from openpyxl.styles import Alignment
from typing import List, Dict

def get_git_urls() -> List[str]:
    """Get list of git URLs from user input."""
    urls = []
    while True:
        url = input("Enter git URL (one at a time, empty line to finish): ").strip()
        if not url:
            break
        urls.append(url)
    return urls

def run_cli_command(git_url: str) -> Dict:
    """Run CLI command for given git URL and return JSON result."""
    command = f"veracode scan --source {git_url} --type repo --format json"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error running command for {git_url}: {e}")
        return {"vulnerabilities": [], "secrets": [], "configs": []}
    
def format_fixes(fix_data: Dict) -> str:
    """Format available fixes step-by-step."""
    if "available" not in fix_data:
        return "N/A"
    
    available_fixes = fix_data.get("available", [])
    fix_strings = []
    
    for available_fix in available_fixes:
        version = available_fix.get('version', 'N/A')
        date = available_fix.get('date', 'N/A')
        fix_strings.append(f"{version} ({date})")
    
    return ", ".join(fix_strings)

def process_results(git_urls: List[str]) -> Dict[str, List[Dict]]:
    """Process results from CLI for all URLs."""
    parsed_results = {"vulnerabilities": [], "secrets": [], "configs": []}
    
    for url in git_urls:
        print(f"Processing {url}...")
        cli_results = run_cli_command(url)

        vulnerabilities = cli_results.get("vulnerabilities", {})
        if vulnerabilities:
            for vuln in vulnerabilities.get("matches", []):
                parsed_results["vulnerabilities"].append({
                    "git_url": url,
                    "id": vuln["vulnerability"]["id"],
                    "description": vuln["vulnerability"]["description"],
                    "artifact_name": vuln["artifact"]["name"] if "artifact" in vuln else "N/A",
                    "artifact_version": vuln["artifact"]["version"] if "artifact" in vuln else "N/A",
                    "artifact_type": vuln["artifact"]["type"] if "artifact" in vuln else "N/A",
                    "risk": vuln["vulnerability"]["risk"] if "risk" in vuln["vulnerability"] else "N/A",
                    "severity": vuln["vulnerability"]["severity"],
                    "CVEs": (", ".join([f"{cwe['cve']} ({cwe['cwe']})" for cwe in vuln["vulnerability"]["cwes"]])) if "cwes" in vuln["vulnerability"] else "N/A",
                    "fixes": format_fixes(vuln["vulnerability"]["fix"]),
                    "raw_json": str(vuln)
                })
        
        for secret in cli_results.get("secrets", []):
            parsed_results["secrets"].append({
                "git_url": url,
                "category": secret.get("Category", "N/A"),
                "severity": secret.get("Severity", "N/A"),
                "start_line": secret.get("StartLine", "N/A"),
                "end_line": secret.get("EndLine", "N/A"),
                "match": secret.get("Match", "N/A"),
                "file_path": secret.get("Target", "N/A"),
                "code": "\n".join([line["Content"] for line in secret["Code"]["Lines"]]) if "Code" in secret else "N/A",
                "raw_json": str(secret)
            })
        
        for config in cli_results.get("configs", []):
            parsed_results["configs"].append({
                "git_url": url,
                "id": config.get("AVDID", "N/A"),
                "target": config.get("Target", "N/A"),
                "title": config.get("Title", "N/A"),
                "type": config.get("Type", "N/A"),                
                "description": config.get("Description", "N/A"),
                "resolution": config.get("Resolution", "N/A"),
                "raw_json": str(config)
            })
    
    return parsed_results

def calculate_cell_length(value: str) -> int:
    """Calculate appropriate cell length for Excel column width."""
    lines = value.splitlines()
    max_length = max(len(line) for line in lines)
    return max_length

def save_to_excel(results: Dict[str, List[Dict]], output_file: str = "combined_iac_report.xlsx"):
    """Save results to Excel with separate tabs using openpyxl."""
    workbook = Workbook()
    workbook.remove(workbook.active)

    text_wrap = Alignment(wrap_text=True)
    
    for sheet_name, data in results.items():
        worksheet = workbook.create_sheet(title=sheet_name.capitalize())
        
        if data:
            # Write headers
            headers = list(data[0].keys())
            worksheet.append([header.replace("_", " ").capitalize() for header in headers])            
            
            # Write data rows
            for row_data in data:
                row_values = [row_data.get(header, "") for header in headers]
                worksheet.append(row_values)
            
            # Apply text wrapping
            dimensions = {}
            for row in worksheet.iter_rows(min_row=2, max_row=worksheet.max_row, min_col=1, max_col=worksheet.max_column):
                for cell in row:
                    if cell.value:
                        dimensions[cell.column_letter] = max(dimensions.get(cell.column_letter, 0), calculate_cell_length(str(cell.value)))
                    if cell.col_idx < worksheet.max_column:
                        cell.alignment = text_wrap
            for col, width in dimensions.items():
                worksheet.column_dimensions[col].width = width + 2

    workbook.save(output_file)
    print(f"Report saved to {output_file}")

def main():
    """Main execution flow."""
    git_urls = get_git_urls()
    file_name = input("Enter the name of the xlsx file to save (defaults to combined_iac_report.xlsx): ")
    if not file_name or file_name.strip() == "":
        file_name = "combined_iac_report.xlsx"
    elif not file_name.endswith(".xlsx"):
        file_name += ".xlsx"

    if not git_urls:
        print("No URLs provided.")
        return

    results = process_results(git_urls)
    save_to_excel(results, file_name)

if __name__ == "__main__":
    main()
