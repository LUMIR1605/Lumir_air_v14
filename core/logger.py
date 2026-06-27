from rich.console import Console

console = Console()

def info(msg):
    console.print(f"[cyan]ℹ[/] {msg}")

def ok(msg):
    console.print(f"[green]✓[/] {msg}")

def warn(msg):
    console.print(f"[yellow]⚠[/] {msg}")

def error(msg):
    console.print(f"[red]✗[/] {msg}")
