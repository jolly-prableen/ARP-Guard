# alerts/dashboard.py
from rich.console import Console
from rich.table import Table

console = Console()

def render_cli_dashboard(trusted_table, alert_history):
    """
    Displays a live-updating CLI table showing current IP-to-MAC trust mappings 
    and recent security alerts.
    """
    # Clear the terminal screen for a clean dashboard view
    console.clear()
    
    # Build a formatted table using the 'rich' library
    table = Table(title="🛡️ ARP Guard - Live Network Monitor")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Status", style="green")

    # Loop through trusted devices and add rows to the table
    for ip, mac in trusted_table.items():
        table.add_row(ip, mac, "Trusted")
        
    # Print the table and total alert counters to the console
    console.print(table)
    console.print(f"\n[bold red]Total Alerts Fired:[/bold red] {len(alert_history)}")
    
    # Show the last 5 alerts if any have occurred
    if alert_history:
        console.print("\n[yellow]Recent Alerts:[/yellow]")
        for alert in alert_history[-5:]:
            console.print(f" - {alert}")