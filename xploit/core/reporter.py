"""
xploit/core/reporter.py - Reporting functionality for XPLOIT results
"""

import logging
import json
import csv
import os
from pathlib import Path
from datetime import datetime
from tabulate import tabulate
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

logger = logging.getLogger("xploit.core.reporter")

class Reporter:
    """Generate reports from XPLOIT results"""
    
    def __init__(self, results, output_dir=None):
        """
        Initialize reporter with results data
        
        Args:
            results (dict): Results data from XPLOIT scan
            output_dir (str, optional): Directory to save reports
        """
        self.results = results
        self.console = Console()
        
        # Set output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path.cwd() / "reports"
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate timestamp for filenames
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def get_summary(self):
        """Get a summary of the results"""
        summary = {
            "target_url": self.results.get("target_url", "Unknown"),
            "target_parameter": self.results.get("target_parameter", "Unknown"),
            "scan_time": self.results.get("scan_summary", {}).get("duration", 0),
            "requests_made": self.results.get("scan_summary", {}).get("requests_made", 0),
            "vulnerabilities_found": len(self.results.get("vulnerabilities", [])),
            "data_points_extracted": len(self.results.get("data_points", [])),
            "unique_responses": self.results.get("scan_summary", {}).get("unique_responses", 0)
        }
        
        return summary
    
    def print_to_console(self):
        """Print results to the console in a nice format"""
        summary = self.get_summary()
        
        # Print header
        self.console.print("\n[bold cyan]XPLOIT Scan Results[/bold cyan]")
        self.console.print(f"[dim]Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
        
        # Print summary panel
        summary_text = f"""
Target URL: {summary['target_url']}
Target Parameter: {summary['target_parameter']}
Scan Time: {summary['scan_time']:.2f} seconds
Requests Made: {summary['requests_made']}
Unique Responses: {summary['unique_responses']}
Vulnerabilities Found: {summary['vulnerabilities_found']}
Data Points Extracted: {summary['data_points_extracted']}
"""
        self.console.print(Panel(summary_text, title="Summary", border_style="blue"))
        
        # Print vulnerabilities if any
        if self.results.get("vulnerabilities"):
            self.console.print("\n[bold red]Vulnerabilities Found:[/bold red]")
            
            vuln_table = Table(show_header=True, header_style="bold")
            vuln_table.add_column("Type")
            vuln_table.add_column("Parameter Value")
            vuln_table.add_column("Description")
            vuln_table.add_column("Confidence")
            
            for vuln in self.results.get("vulnerabilities", []):
                vuln_table.add_row(
                    vuln.get("type", "Unknown"),
                    vuln.get("parameter_value", "N/A"),
                    vuln.get("description", "N/A"),
                    vuln.get("confidence", "N/A")
                )
            
            self.console.print(vuln_table)
            
            # Show evidence for the first vulnerability as an example
            if self.results.get("vulnerabilities"):
                first_vuln = self.results["vulnerabilities"][0]
                if "evidence" in first_vuln:
                    self.console.print("\n[bold]Evidence Example (first vulnerability):[/bold]")
                    evidence = first_vuln["evidence"]
                    if len(evidence) > 500:
                        evidence = evidence[:500] + "..."
                    
                    if "application/json" in first_vuln.get("content_type", ""):
                        try:
                            # Try to format as JSON
                            syntax = Syntax(json.dumps(json.loads(evidence), indent=2), "json")
                            self.console.print(syntax)
                        except:
                            self.console.print(evidence)
                    else:
                        self.console.print(evidence)
        else:
            self.console.print("\n[green]No vulnerabilities were detected.[/green]")
        
        # Print data points if any
        if self.results.get("data_points"):
            data_count = len(self.results["data_points"])
            self.console.print(f"\n[bold green]Data Points Extracted: {data_count}[/bold green]")
            
            if data_count > 0:
                # Create a table for data points
                data_table = Table(show_header=True, header_style="bold")
                data_table.add_column("Type")
                data_table.add_column("Parameter Value")
                data_table.add_column("Value")
                data_table.add_column("Confidence")
                
                # Show up to 10 data points
                for dp in self.results.get("data_points", [])[:10]:
                    value = dp.get("value", "N/A")
                    if isinstance(value, str) and len(value) > 50:
                        value = value[:50] + "..."
                        
                    data_table.add_row(
                        dp.get("data_type", "Unknown"),
                        dp.get("parameter_value", "N/A"),
                        value,
                        dp.get("confidence", "N/A")
                    )
                
                self.console.print(data_table)
                
                if data_count > 10:
                    self.console.print(f"[dim]... and {data_count - 10} more data points not shown[/dim]")
        
        # Print recommendations
        self.console.print("\n[bold]Recommendations:[/bold]")
        if self.results.get("vulnerabilities"):
            self.console.print("• [yellow]The target appears to be vulnerable. Consider implementing proper input validation and access controls.[/yellow]")
            if any("SQLi" in v.get("type", "") for v in self.results.get("vulnerabilities", [])):
                self.console.print("• [yellow]SQL Injection vulnerability detected. Use parameterized queries instead of string concatenation.[/yellow]")
            if any("IDOR" in v.get("type", "") for v in self.results.get("vulnerabilities", [])):
                self.console.print("• [yellow]IDOR vulnerability detected. Implement proper authorization checks for all resources.[/yellow]")
        else:
            self.console.print("• [green]No obvious vulnerabilities were detected. Continue to monitor and test regularly.[/green]")
    
    def save_json(self, filename=None):
        """Save results as JSON"""
        if not filename:
            filename = f"xploit_results_{self.timestamp}.json"
        
        output_path = self.output_dir / filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"JSON report saved to {output_path}")
        return output_path
    
    def save_csv(self, filename=None):
        """Save results as CSV (data points only)"""
        if not filename:
            filename = f"xploit_data_{self.timestamp}.csv"
        
        output_path = self.output_dir / filename
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write headers
            writer.writerow(["ID", "Parameter Value", "Data Type", "Value", "Confidence"])
            
            # Write data rows
            for dp in self.results.get("data_points", []):
                writer.writerow([
                    dp.get("id", ""),
                    dp.get("parameter_value", ""),
                    dp.get("data_type", ""),
                    dp.get("value", ""),
                    dp.get("confidence", "")
                ])
        
        logger.info(f"CSV report saved to {output_path}")
        return output_path
    
    def save_html(self, filename=None):
        """Save results as HTML report"""
        if not filename:
            filename = f"xploit_report_{self.timestamp}.html"
        
        output_path = self.output_dir / filename
        
        # Get summary data
        summary = self.get_summary()
        
        # Basic HTML template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XPLOIT Scan Results</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .summary {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary dl {{
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 10px;
        }}
        .summary dt {{
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        table th, table td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        table th {{
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        table tr:hover {{
            background-color: #f1f1f1;
        }}
        .vulnerability {{
            background-color: #fff0f0;
            padding: 15px;
            border-left: 4px solid #ff4444;
            margin-bottom: 15px;
            border-radius: 0 5px 5px 0;
        }}
        .data-point {{
            background-color: #f0f8ff;
            padding: 15px;
            border-left: 4px solid #44aaff;
            margin-bottom: 15px;
            border-radius: 0 5px 5px 0;
        }}
        .evidence {{
            background-color: #f5f5f5;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .recommendations {{
            background-color: #f0fff0;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 10px;
            border-top: 1px solid #eee;
            font-size: 0.8em;
            color: #777;
        }}