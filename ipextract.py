import os
import ipaddress
from tqdm import tqdm
import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn, BarColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich import print as rprint
from datetime import datetime
import chardet
import re
from typing import List, Tuple

console = Console()

def format_number(num):
    """Format numbers with thousands separator"""
    return "{:,}".format(num)

class IPExtractor:
    def __init__(self, folder_path, output_file, expand_all=False):
        self.folder_path = folder_path
        self.output_file = output_file
        self.error_log_file = 'invalid_err_log.txt'
        self.expand_all = expand_all
        self.unique_ips = set()
        self.invalid_entries = []
        self.stats = {
            'files_processed': 0,
            'lines_processed': 0,
            'valid_ipv4': 0,
            'valid_subnets': 0,
            'invalid_entries': 0,
            'ipv6_skipped': 0,
            'start_time': datetime.now(),
            'large_subnets_skipped': 0,
            'files_with_errors': 0,
            'recovered_ips': 0
        }

    def log_invalid_entry(self, file_name, line_number, line, error):
        """Log invalid entry with context"""
        self.invalid_entries.append({
            'file': file_name,
            'line_number': line_number,
            'content': line,
            'error': str(error)
        })

    def detect_file_encoding(self, file_path):
        """Detect the encoding of a file"""
        try:
            with open(file_path, 'rb') as file:
                raw_data = file.read()
                result = chardet.detect(raw_data)
                return result['encoding'] or 'utf-8'
        except Exception:
            return 'utf-8'

    def extract_potential_ips_from_text(self, text: str) -> List[str]:
        """Extract potential IPv4 addresses from text using regex"""
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        potential_ips = re.findall(ipv4_pattern, text)
        valid_ips = []
        
        for ip in potential_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    valid_ips.append(str(ip_obj))
            except ValueError:
                continue
        
        return valid_ips

    def display_startup_banner(self):
        """Display startup banner with configuration details"""
        console.print(Panel.fit(
            "[bold blue]IPv4 Address Extractor[/bold blue]\n\n"
            f"[yellow]Folder:[/yellow] {self.folder_path}\n"
            f"[yellow]Output:[/yellow] {self.output_file}\n"
            f"[yellow]Error Log:[/yellow] {self.error_log_file}\n"
            f"[yellow]Auto-expand large subnets:[/yellow] {'Yes' if self.expand_all else 'No'}\n"
            f"[yellow]Start time:[/yellow] {self.stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}",
            title="Configuration",
            border_style="blue"
        ))

    def display_final_stats(self):
        """Display final statistics in a formatted panel"""
        duration = datetime.now() - self.stats['start_time']
        
        stats_text = (
            f"[green]Files Processed Successfully:[/green] {format_number(self.stats['files_processed'])}\n"
            f"[red]Files With Errors:[/red] {format_number(self.stats['files_with_errors'])}\n"
            f"[green]Lines Processed:[/green] {format_number(self.stats['lines_processed'])}\n"
            f"[green]Valid IPv4 Addresses:[/green] {format_number(self.stats['valid_ipv4'])}\n"
            f"[green]Valid IPv4 Subnets Expanded:[/green] {format_number(self.stats['valid_subnets'])}\n"
            f"[yellow]IPv6 Addresses/Subnets Skipped:[/yellow] {format_number(self.stats['ipv6_skipped'])}\n"
            f"[red]Invalid Entries:[/red] {format_number(self.stats['invalid_entries'])}\n"
            f"[green]Recovered IPv4 Addresses:[/green] {format_number(self.stats.get('recovered_ips', 0))}\n"
            f"[red]Large Subnets Skipped:[/red] {format_number(self.stats['large_subnets_skipped'])}\n"
            f"[blue]Total Unique IPv4 Addresses:[/blue] {format_number(len(self.unique_ips))}\n"
            f"[cyan]Duration:[/cyan] {str(duration).split('.')[0]}\n"
            f"[cyan]Output File:[/cyan] {self.output_file}\n"
            f"[cyan]Error Log:[/cyan] {self.error_log_file}"
        )
        
        console.print(Panel(
            stats_text,
            title="[bold]Processing Complete[/bold]",
            border_style="green"
        ))

    def read_file_lines(self, file_path):
        """Read file lines with proper encoding detection"""
        if file_path.endswith('.DS_Store'):
            return []

        try:
            encoding = self.detect_file_encoding(file_path)
            with open(file_path, 'r', encoding=encoding, errors='replace') as file:
                return file.readlines()
        except Exception as e:
            console.print(f"[red]Error reading file {os.path.basename(file_path)}: {str(e)}[/red]")
            self.stats['files_with_errors'] += 1
            self.log_invalid_entry(os.path.basename(file_path), 0, "", f"File read error: {str(e)}")
            return []

    def process_subnet(self, subnet, line):
        """Process a subnet and return True if processed successfully"""
        num_ips = subnet.num_addresses
        if num_ips > 1000:
            if not self.expand_all:
                rprint(f"\n[yellow]Warning:[/yellow] Large subnet detected ({line} - {format_number(num_ips)} addresses)")
                if not Confirm.ask("Do you want to expand this subnet?"):
                    self.stats['large_subnets_skipped'] += 1
                    return False
            
            batch_size = 10000
            for i in range(0, num_ips, batch_size):
                batch = list(subnet)[i:i + batch_size]
                self.unique_ips.update(str(ip) for ip in batch)
        else:
            self.unique_ips.update(str(ip) for ip in subnet)
        
        return True
    def process_invalid_entries(self) -> Tuple[int, int]:
        """Process invalid entries to extract any valid IPv4 addresses"""
        console.print("\n[yellow]Processing invalid entries for potential IPv4 addresses...[/yellow]")
        
        processed_count = 0
        recovered_ips_count = 0
        remaining_invalid_entries = []

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn()
        ) as progress:
            task = progress.add_task(
                "[cyan]Processing invalid entries", 
                total=len(self.invalid_entries)
            )

            for entry in self.invalid_entries:
                content = entry['content']
                recovered_ips = self.extract_potential_ips_from_text(content)
                
                if recovered_ips:
                    self.unique_ips.update(recovered_ips)
                    recovered_ips_count += len(recovered_ips)
                    entry['recovered_ips'] = recovered_ips
                    entry['error'] += f" (Recovered {len(recovered_ips)} valid IPv4 addresses)"
                else:
                    entry['recovered_ips'] = []
                
                remaining_invalid_entries.append(entry)
                processed_count += 1
                progress.advance(task)

        self.invalid_entries = remaining_invalid_entries
        return processed_count, recovered_ips_count

    def write_error_log(self):
        """Write invalid entries to error log file"""
        console.print(f"\n[yellow]Writing error log to {self.error_log_file}...[/yellow]")
        
        with open(self.error_log_file, 'w', encoding='utf-8') as log_file:
            log_file.write("=== IPv4 Extraction Error Log ===\n")
            log_file.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_file.write(f"Source folder: {self.folder_path}\n")
            log_file.write("=" * 50 + "\n\n")
            
            if not self.invalid_entries:
                log_file.write("No invalid entries found.\n")
                return
                
            for entry in self.invalid_entries:
                log_file.write(f"File: {entry['file']}\n")
                log_file.write(f"Line Number: {entry['line_number']}\n")
                log_file.write(f"Content: {entry['content']}\n")
                log_file.write(f"Error: {entry['error']}\n")
                
                if 'recovered_ips' in entry and entry['recovered_ips']:
                    log_file.write("Recovered IPv4 Addresses:\n")
                    for ip in entry['recovered_ips']:
                        log_file.write(f"  - {ip}\n")
                
                log_file.write("-" * 50 + "\n")

    def extract_ips(self):
        """Main method to extract IPv4 addresses and subnets"""
        self.display_startup_banner()
        
        files = [f for f in os.listdir(self.folder_path) 
                if os.path.isfile(os.path.join(self.folder_path, f)) 
                and not f.startswith('.')]
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn()
        ) as progress:
            
            overall_task = progress.add_task(
                "[cyan]Overall Progress", 
                total=len(files)
            )
            
            for file_name in files:
                file_path = os.path.join(self.folder_path, file_name)
                progress.update(overall_task, description=f"[cyan]Processing {file_name}")
                
                lines = self.read_file_lines(file_path)
                
                for line_number, line in enumerate(lines, 1):
                    self.stats['lines_processed'] += 1
                    line = line.strip()
                    
                    if not line:
                        continue
                        
                    try:
                        if '/' not in line:
                            ip = ipaddress.ip_address(line)
                            if isinstance(ip, ipaddress.IPv6Address):
                                self.stats['ipv6_skipped'] += 1
                                self.log_invalid_entry(file_name, line_number, line, "IPv6 address skipped")
                                continue
                            self.unique_ips.add(str(ip))
                            self.stats['valid_ipv4'] += 1
                        else:
                            network = ipaddress.ip_network(line, strict=False)
                            if isinstance(network, ipaddress.IPv6Network):
                                self.stats['ipv6_skipped'] += 1
                                self.log_invalid_entry(file_name, line_number, line, "IPv6 subnet skipped")
                                continue
                            
                            if self.process_subnet(network, line):
                                self.stats['valid_subnets'] += 1
                                
                    except ValueError as e:
                        self.stats['invalid_entries'] += 1
                        self.log_invalid_entry(file_name, line_number, line, f"Invalid IP/subnet: {str(e)}")
                        continue
                
                self.stats['files_processed'] += 1
                progress.advance(overall_task)

        # Process invalid entries for potential IPv4 addresses
        processed_count, recovered_ips_count = self.process_invalid_entries()
        if recovered_ips_count > 0:
            console.print(f"[green]Recovered {recovered_ips_count} valid IPv4 addresses from {processed_count} invalid entries![/green]")
        self.stats['recovered_ips'] = recovered_ips_count
        
        # Write unique IPs to output file
        console.print("\n[cyan]Writing unique IPv4 addresses to output file...[/cyan]")
        with Progress(
            SpinnerColumn(),
            *Progress.get_default_columns(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            write_task = progress.add_task("[cyan]Writing IPs...", total=len(self.unique_ips))
            
            with open(self.output_file, 'w', encoding='utf-8') as out_file:
                sorted_ips = sorted(self.unique_ips, key=lambda ip: [int(octet) for octet in ip.split('.')])
                for ip in sorted_ips:
                    out_file.write(ip + '\n')
                    progress.advance(write_task)
        
        # Write error log
        self.write_error_log()
        self.display_final_stats()

@click.command()
@click.argument('folder_path', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--expand-all', '-e', is_flag=True, help='Automatically expand all subnets without prompting')
@click.option('--no-progress', '-np', is_flag=True, help='Disable progress bars')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-error output')
def main(folder_path, output_file, expand_all, no_progress, quiet):
    """
    Extract IPv4 addresses and subnets from files in FOLDER_PATH and save to OUTPUT_FILE.
    
    Arguments:
        FOLDER_PATH: Path to the folder containing files with IP addresses
        OUTPUT_FILE: Path where the extracted IPv4 addresses will be saved
    """
    try:
        if not quiet:
            console.print("[bold blue]Starting IPv4 Address Extractor...[/bold blue]")
            
        if not os.path.isdir(folder_path):
            console.print(f"[red]Error: Folder '{folder_path}' does not exist![/red]")
            return 1
            
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                console.print(f"[red]Error: Cannot create output directory: {str(e)}[/red]")
                return 1

        extractor = IPExtractor(folder_path, output_file, expand_all)
        extractor.extract_ips()
        return 0

    except KeyboardInterrupt:
        console.print("\n[red]Operation cancelled by user![/red]")
        return 130
    except Exception as e:
        console.print(f"\n[red]An error occurred: {str(e)}[/red]")
        if not quiet:
            console.print_exception()
        return 1

if __name__ == "__main__":
    exit(main())