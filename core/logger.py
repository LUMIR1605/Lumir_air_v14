from rich.console import Console

console = Console()

def info(msg):
    """Log info message"""
    console.print(f"[cyan]ℹ[/] {msg}")

def ok(msg):
    """Log success message"""
    console.print(f"[green]✓[/] {msg}")

def warn(msg):
    """Log warning message"""
    console.print(f"[yellow]⚠[/] {msg}")

def error(msg):
    """Log error message"""
    console.print(f"[red]✗[/] {msg}")
