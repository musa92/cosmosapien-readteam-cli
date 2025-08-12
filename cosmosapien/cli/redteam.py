"""Red-teaming CLI commands for Cosmosapien."""

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live

from ..core.config import ConfigManager
from ..core.model_library import ModelLibrary
from ..core.router import Router
from ..redteam.engine import AttackRouter
from ..redteam.packs import ScenarioPackManager
from ..redteam.models import AttackMode, AttackRequest

# Initialize Typer app
redteam_app = typer.Typer(
    name="redteam",
    help="Red-teaming toolkit for evaluating LLM safety and identifying vulnerabilities",
    add_completion=False,
)

# Initialize Rich console
console = Console()

# Global instances
config_manager = ConfigManager()
model_library = ModelLibrary(config_manager)
router = Router(config_manager)
attack_router = AttackRouter(config_manager, model_library, router)
pack_manager = ScenarioPackManager()


@redteam_app.command()
def run(
    pack: str = typer.Argument(..., help="Scenario pack to use for attacks"),
    models: List[str] = typer.Option(
        ["llama:llama3.2:3b"], 
        "--models", "-m", 
        help="Target models to attack (provider:model format)"
    ),
    mode: AttackMode = typer.Option(
        AttackMode.SEQUENTIAL, 
        "--mode", 
        help="Attack orchestration mode"
    ),
    output: Optional[str] = typer.Option(
        None, 
        "--output", "-o", 
        help="Output file for results"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Run red-teaming attacks against target models."""
    
    async def _run():
        try:
            # Validate scenario pack
            if not pack_manager.is_pack_installed(pack):
                console.print(f"[red]Scenario pack '{pack}' not found. Install it first with 'cosmo redteam packs install'[/red]")
                raise typer.Exit(1)
            
            # Validate target models
            valid_models = []
            for model in models:
                provider, model_name = model.split(":", 1)
                if not model_library.get_model(model):
                    console.print(f"[yellow]Warning: Model '{model}' not found in library[/yellow]")
                else:
                    valid_models.append(model)
            
            if not valid_models:
                console.print("[red]No valid target models specified[/red]")
                raise typer.Exit(1)
            
            console.print(f"[bold blue]Starting red-teaming attack[/bold blue]")
            console.print(f"Pack: {pack}")
            console.print(f"Target models: {', '.join(valid_models)}")
            console.print(f"Attack mode: {mode.value}")
            console.print()
            
            # Create attack request
            request = AttackRequest(
                scenario_pack=pack,
                target_models=valid_models,
                attack_mode=mode
            )
            
            # Execute attack
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Executing attacks...", total=None)
                
                result = await attack_router.execute_attack(request)
            
            if result.success:
                console.print(f"[green]Attack completed successfully![/green]")
                console.print(f"Run ID: {result.run_id}")
                console.print(f"Execution time: {result.execution_time:.2f}s")
                console.print(f"Tokens consumed: {result.tokens_consumed:,}")
                console.print(f"Estimated cost: ${result.estimated_cost:.4f}")
                console.print(f"Findings: {len(result.findings)}")
                
                # Display findings summary
                if result.findings:
                    console.print("\n[bold]Findings Summary:[/bold]")
                    findings_table = Table(title="Vulnerability Findings")
                    findings_table.add_column("Model", style="cyan")
                    findings_table.add_column("Category", style="magenta")
                    findings_table.add_column("Severity", style="yellow")
                    findings_table.add_column("Novelty", style="blue")
                    findings_table.add_column("Status", style="green")
                    
                    for finding in result.findings:
                        severity_color = {
                            0: "white", 1: "green", 2: "yellow", 
                            3: "red", 4: "red", 5: "red"
                        }.get(finding.severity_score.value, "white")
                        
                        findings_table.add_row(
                            f"{finding.model_provider}:{finding.model_name}",
                            finding.harm_category.value.replace('_', ' ').title(),
                            f"[{severity_color}]{finding.severity_score.name}[/{severity_color}]",
                            f"{finding.novelty_score:.2f}",
                            finding.status.value
                        )
                    
                    console.print(findings_table)
                
                # Save results if output specified
                if output:
                    output_path = Path(output)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Save as JSON
                    import json
                    with open(output_path, 'w') as f:
                        json.dump(result.dict(), f, indent=2, default=str)
                    
                    console.print(f"\n[green]Results saved to: {output_path}[/green]")
                
            else:
                console.print(f"[red]Attack failed: {result.error}[/red]")
                raise typer.Exit(1)
                
        except Exception as e:
            console.print(f"[red]Error during attack execution: {e}[/red]")
            raise typer.Exit(1)
    
    asyncio.run(_run())


@redteam_app.command()
def packs(
    action: str = typer.Argument(..., help="Action: list, install, uninstall, show, search"),
    pack_id: Optional[str] = typer.Argument(None, help="Pack ID for install/uninstall/show"),
    pack_path: Optional[str] = typer.Argument(None, help="Path to pack file for install")
):
    """Manage scenario packs for red-teaming."""
    
    if action == "list":
        packs = pack_manager.list_packs()
        
        if not packs:
            console.print("[yellow]No scenario packs available[/yellow]")
            return
        
        table = Table(title="Available Scenario Packs")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="blue")
        table.add_column("Version", style="green")
        table.add_column("Safety", style="yellow")
        table.add_column("Type", style="magenta")
        table.add_column("Installed", style="red")
        
        for pack_id, pack_info in packs.items():
            installed_icon = "✓" if pack_info.get('installed', False) else "✗"
            table.add_row(
                pack_id,
                pack_info.get('name', 'Unknown'),
                pack_info.get('version', 'Unknown'),
                pack_info.get('safety_level', 'Unknown'),
                pack_info.get('type', 'Unknown'),
                installed_icon
            )
        
        console.print(table)
        
        # Show statistics
        stats = pack_manager.get_pack_statistics()
        console.print(f"\n[bold]Pack Statistics:[/bold]")
        console.print(f"Installed: {stats['total_installed']}")
        console.print(f"Built-in: {stats['total_builtin']}")
        console.print(f"Packs directory: {stats['packs_directory']}")
    
    elif action == "install":
        if not pack_path:
            console.print("[red]Pack path required for install[/red]")
            raise typer.Exit(1)
        
        if pack_manager.install_pack(pack_path, pack_id):
            console.print(f"[green]Successfully installed pack: {pack_id or 'auto-generated ID'}[/green]")
        else:
            console.print("[red]Failed to install pack[/red]")
            raise typer.Exit(1)
    
    elif action == "uninstall":
        if not pack_id:
            console.print("[red]Pack ID required for uninstall[/red]")
            raise typer.Exit(1)
        
        if pack_manager.uninstall_pack(pack_id):
            console.print(f"[green]Successfully uninstalled pack: {pack_id}[/green]")
        else:
            console.print("[red]Failed to uninstall pack[/red]")
            raise typer.Exit(1)
    
    elif action == "show":
        if not pack_id:
            console.print("[red]Pack ID required for show[/red]")
            raise typer.Exit(1)
        
        pack_info = pack_manager.get_pack_info(pack_id)
        if not pack_info:
            console.print(f"[red]Pack '{pack_id}' not found[/red]")
            raise typer.Exit(1)
        
        console.print(Panel(
            f"[bold]Name:[/bold] {pack_info['name']}\n"
            f"[bold]Description:[/bold] {pack_info['description']}\n"
            f"[bold]Version:[/bold] {pack_info['version']}\n"
            f"[bold]Safety Level:[/bold] {pack_info['safety_level']}\n"
            f"[bold]Scenarios:[/bold] {len(pack_info['scenarios'])}\n"
            f"[bold]Tags:[/bold] {', '.join(pack_info.get('tags', []))}",
            title=f"Pack: {pack_id}",
            border_style="blue"
        ))
        
        # Show scenarios
        if pack_info['scenarios']:
            console.print("\n[bold]Scenarios:[/bold]")
            for i, scenario in enumerate(pack_info['scenarios'][:5], 1):  # Show first 5
                console.print(f"{i}. {scenario.get('name', 'Unnamed')}")
                console.print(f"   {scenario.get('prompt', '')[:100]}...")
                console.print()
            
            if len(pack_info['scenarios']) > 5:
                console.print(f"... and {len(pack_info['scenarios']) - 5} more scenarios")
    
    elif action == "search":
        if not pack_id:
            console.print("[red]Search query required[/red]")
            raise typer.Exit(1)
        
        results = pack_manager.search_packs(pack_id)
        
        if not results:
            console.print(f"[yellow]No packs found matching '{pack_id}'[/yellow]")
            return
        
        console.print(f"[bold]Search Results for '{pack_id}':[/bold]")
        table = Table()
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="blue")
        table.add_column("Description", style="green")
        table.add_column("Type", style="magenta")
        
        for pack_id, pack_info in results.items():
            table.add_row(
                pack_id,
                pack_info.get('name', 'Unknown'),
                pack_info.get('description', '')[:50] + "..." if len(pack_info.get('description', '')) > 50 else pack_info.get('description', ''),
                pack_info.get('type', 'Unknown')
            )
        
        console.print(table)
    
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        console.print("Available actions: list, install, uninstall, show, search")
        raise typer.Exit(1)


@redteam_app.command()
def findings(
    run_id: Optional[str] = typer.Argument(None, help="Show findings for specific run ID"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json, csv)")
):
    """List and show vulnerability findings."""
    
    if run_id:
        # Show findings for specific run
        # TODO: Implement finding retrieval by run ID
        console.print(f"[yellow]Showing findings for run {run_id} - not yet implemented[/yellow]")
    else:
        # Show all findings
        stats = attack_router.get_attack_stats()
        
        if stats['total_runs'] == 0:
            console.print("[yellow]No attack runs found[/yellow]")
            return
        
        console.print(f"[bold]Attack Statistics:[/bold]")
        console.print(f"Total runs: {stats['total_runs']}")
        console.print(f"Successful runs: {stats['successful_runs']}")
        console.print(f"Failed runs: {stats['failed_runs']}")
        console.print(f"Total findings: {stats['total_findings']}")
        console.print(f"Average execution time: {stats['avg_execution_time']:.2f}s")
        console.print(f"Total tokens: {stats['total_tokens']:,}")
        console.print(f"Total cost: ${stats['total_cost']:.4f}")


@redteam_app.command()
def export(
    run_id: str = typer.Argument(..., help="Run ID to export"),
    format: str = typer.Option("json", "--format", "-f", help="Export format (json, kaggle, csv, parquet)"),
    output: str = typer.Option("findings_export", "--output", "-o", help="Output filename (without extension)")
):
    """Export findings in various formats for analysis or submission."""
    
    console.print(f"[yellow]Export functionality for run {run_id} - not yet implemented[/yellow]")
    console.print("Supported formats: json, kaggle, csv, parquet")


@redteam_app.command()
def analyze(
    run_id: str = typer.Argument(..., help="Run ID to analyze"),
    format: str = typer.Option("html", "--format", "-f", help="Report format (html, markdown, pdf)"),
    output: str = typer.Option("redteam_report", "--output", "-o", help="Output filename (without extension)")
):
    """Generate expert-level analysis reports with charts and visualizations."""
    
    console.print(f"[yellow]Analysis functionality for run {run_id} - not yet implemented[/yellow]")
    console.print("Supported formats: html, markdown, pdf")


@redteam_app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to"),
    open_browser: bool = typer.Option(True, "--open", help="Open browser automatically")
):
    """Launch FastAPI dashboard for browsing findings interactively."""
    
    console.print(f"[yellow]Dashboard functionality - not yet implemented[/yellow]")
    console.print(f"Would launch on {host}:{port}")


@redteam_app.command()
def config():
    """Show red-teaming configuration."""
    
    config = attack_router.config
    
    console.print(Panel(
        f"[bold]Attack Router Settings:[/bold]\n"
        f"Max concurrent attacks: {config.max_concurrent_attacks}\n"
        f"Attack timeout: {config.attack_timeout}s\n"
        f"Retry attempts: {config.retry_attempts}\n\n"
        f"[bold]Novelty Detection:[/bold]\n"
        f"Novelty threshold: {config.novelty_threshold}\n"
        f"Similarity method: {config.similarity_method}\n\n"
        f"[bold]Redaction Settings:[/bold]\n"
        f"Enable redaction: {config.enable_redaction}\n"
        f"Redaction rules: {len(config.redaction_rules)}\n\n"
        f"[bold]Reporting:[/bold]\n"
        f"Auto-generate reports: {config.auto_generate_reports}\n"
        f"Report formats: {', '.join(config.report_formats)}\n\n"
        f"[bold]Safety:[/bold]\n"
        f"Safety checks: {config.safety_checks}\n"
        f"Max severity: {config.max_severity.name}",
        title="Red-Teaming Configuration",
        border_style="blue"
    ))


@redteam_app.command()
def demo():
    """Run a demonstration red-teaming session."""
    
    console.print("[bold blue]Red-Teaming Toolkit Demo[/bold blue]")
    console.print("This will run a safe demonstration using the 'policy_edges' pack.")
    console.print()
    
    # Check if demo pack is available
    if not pack_manager.is_pack_installed("policy_edges"):
        console.print("[yellow]Installing demo pack...[/yellow]")
        # Try to install from builtin
        demo_pack = pack_manager.get_pack("policy_edges")
        if demo_pack:
            # Save as installed pack
            pack_file = pack_manager.packs_dir / "policy_edges.json"
            import json
            with open(pack_file, 'w') as f:
                json.dump(demo_pack.dict(), f, indent=2, default=str)
            
            # Update registry
            pack_manager.registry["policy_edges"] = {
                'name': demo_pack.name,
                'version': demo_pack.version,
                'description': demo_pack.description,
                'safety_level': demo_pack.safety_level,
                'installed_at': str(Path().cwd()),
                'source': 'builtin'
            }
            pack_manager._save_registry()
            console.print("[green]Demo pack installed successfully![/green]")
        else:
            console.print("[red]Failed to install demo pack[/red]")
            raise typer.Exit(1)
    
    console.print("[green]Demo pack ready![/green]")
    console.print()
    console.print("To run the demo:")
    console.print("  cosmo redteam run policy_edges --models llama:llama3.2:3b")
    console.print()
    console.print("To see available packs:")
    console.print("  cosmo redteam packs list")
    console.print()
    console.print("To get help:")
    console.print("  cosmo redteam --help") 