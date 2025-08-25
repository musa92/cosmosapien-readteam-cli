"""
Advanced CLI commands for automated vulnerability testing.
"""
import asyncio
import json
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from cosmosapien.config.loader import load_config, DEFAULT_CONFIG
from cosmosapien.models.local_rules import LocalRulesModel
from cosmosapien.models.ollama_model import OllamaModel
from cosmosapien.detectors.advanced_detector import AdvancedVulnerabilityDetector, DetectionStrategy
from cosmosapien.redteam.automated_generator import AutomatedRedTeamGenerator, AttackVector, HarmCategory
from cosmosapien.redteam.orchestrator import AutomatedVulnerabilityTester

app = typer.Typer()
console = Console()

def load_model(model_config: dict):
    """Create model instance from config."""
    model_type = model_config["type"]
    if model_type == "local_rules":
        return LocalRulesModel()
    elif model_type == "ollama":
        return OllamaModel(model_config.get("name"))
    else:
        raise ValueError(f"Unknown model type: {model_type}")

@app.command()
def run_automated_test(
    num_cases: int = typer.Option(20, "--cases", "-n", help="Number of test cases to generate"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    config_path: Optional[Path] = typer.Option(DEFAULT_CONFIG, "--config", help="Config file path"),
    format: str = typer.Option("json", "--format", "-f", help="Output format (json, csv)"),
    harm_categories: Optional[List[str]] = typer.Option(None, "--harm", help="Specific harm categories to test"),
    attack_vectors: Optional[List[str]] = typer.Option(None, "--attack", help="Specific attack vectors to use"),
    include_escalation: bool = typer.Option(True, "--escalation/--no-escalation", help="Include escalation tests"),
    max_concurrent: int = typer.Option(3, "--concurrent", help="Max concurrent tests")
):
    """
    Run automated vulnerability testing with generated prompts.
    """
    asyncio.run(_run_automated_test_async(
        num_cases, output, config_path, format, harm_categories, 
        attack_vectors, include_escalation, max_concurrent
    ))

async def _run_automated_test_async(
    num_cases: int,
    output: Optional[Path],
    config_path: Optional[Path],
    format: str,
    harm_categories: Optional[List[str]],
    attack_vectors: Optional[List[str]],
    include_escalation: bool,
    max_concurrent: int
):
    """Async implementation of automated testing."""
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Load configuration
        task = progress.add_task("Loading configuration...", total=None)
        config = load_config(str(config_path) if config_path else None)
        
        # Create model
        progress.update(task, description="Initializing model...")
        model_configs = config["models"]
        # Use first model for now - could be extended to test multiple models
        model = load_model(model_configs[0])
        
        # Parse harm categories and attack vectors
        parsed_harm_categories = None
        if harm_categories:
            try:
                parsed_harm_categories = [HarmCategory(cat) for cat in harm_categories]
            except ValueError as e:
                console.print(f"[red]Invalid harm category: {e}[/red]")
                return
        
        parsed_attack_vectors = None
        if attack_vectors:
            try:
                parsed_attack_vectors = [AttackVector(vec) for vec in attack_vectors]
            except ValueError as e:
                console.print(f"[red]Invalid attack vector: {e}[/red]")
                return
        
        # Initialize tester
        progress.update(task, description="Initializing automated tester...")
        detector = AdvancedVulnerabilityDetector()
        generator = AutomatedRedTeamGenerator()
        tester = AutomatedVulnerabilityTester(model, detector, generator)
        
        # Run tests
        progress.update(task, description=f"Running {num_cases} automated tests...")
        
        test_suite = await tester.run_comprehensive_test(
            num_test_cases=num_cases,
            harm_categories=parsed_harm_categories,
            attack_vectors=parsed_attack_vectors,
            include_escalation_tests=include_escalation,
            max_concurrent=max_concurrent
        )
        
        progress.update(task, description="Generating report...")
        
        # Display summary
        stats = test_suite.summary_stats
        
        console.print("\n[bold green]Automated Vulnerability Test Results[/bold green]")
        console.print(f"Total tests: {stats['total_tests']}")
        console.print(f"Vulnerabilities detected: {stats['vulnerabilities_detected']}")
        console.print(f"Vulnerability rate: {stats['vulnerability_rate']:.2%}")
        console.print(f"Total runtime: {test_suite.total_runtime:.2f}s")
        
        # Category breakdown table
        if stats.get('category_breakdown'):
            table = Table(title="Vulnerability Categories Detected")
            table.add_column("Category", style="cyan")
            table.add_column("Count", style="magenta")
            table.add_column("Percentage", style="green")
            
            for category, count in stats['category_breakdown'].items():
                percentage = (count / stats['total_tests']) * 100
                table.add_row(category, str(count), f"{percentage:.1f}%")
            
            console.print(table)
        
        # Attack vector success rates
        if stats.get('attack_success_rates'):
            table = Table(title="Attack Vector Success Rates")
            table.add_column("Attack Vector", style="cyan")
            table.add_column("Success Rate", style="magenta")
            
            for vector, rate in stats['attack_success_rates'].items():
                table.add_row(vector, f"{rate:.2%}")
            
            console.print(table)
        
        # Export results
        if output:
            progress.update(task, description="Exporting results...")
            result = tester.export_results(test_suite, format, str(output))
            console.print(f"[green]{result}[/green]")
        else:
            # Print summary to stdout
            if format == "json":
                summary_json = {
                    "summary": stats,
                    "runtime": test_suite.total_runtime,
                    "timestamp": test_suite.timestamp
                }
                console.print(json.dumps(summary_json, indent=2))

@app.command()
def generate_prompts(
    num_prompts: int = typer.Option(10, "--count", "-n", help="Number of prompts to generate"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    harm_categories: Optional[List[str]] = typer.Option(None, "--harm", help="Harm categories"),
    attack_vectors: Optional[List[str]] = typer.Option(None, "--attack", help="Attack vectors"),
    difficulty_min: int = typer.Option(1, "--min-difficulty", help="Minimum difficulty level"),
    difficulty_max: int = typer.Option(5, "--max-difficulty", help="Maximum difficulty level")
):
    """
    Generate red team prompts for manual testing.
    """
    generator = AutomatedRedTeamGenerator()
    
    # Parse categories and vectors
    parsed_harm_categories = None
    if harm_categories:
        try:
            parsed_harm_categories = [HarmCategory(cat) for cat in harm_categories]
        except ValueError as e:
            console.print(f"[red]Invalid harm category: {e}[/red]")
            return
    
    parsed_attack_vectors = None
    if attack_vectors:
        try:
            parsed_attack_vectors = [AttackVector(vec) for vec in attack_vectors]
        except ValueError as e:
            console.print(f"[red]Invalid attack vector: {e}[/red]")
            return
    
    # Generate prompts
    prompts = generator.generate_test_cases(
        num_cases=num_prompts,
        harm_categories=parsed_harm_categories,
        attack_vectors=parsed_attack_vectors,
        difficulty_range=(difficulty_min, difficulty_max)
    )
    
    # Format output
    output_data = []
    for prompt in prompts:
        output_data.append({
            "prompt": prompt.prompt,
            "attack_vector": prompt.attack_vector.value,
            "harm_category": prompt.harm_category.value,
            "difficulty_level": prompt.difficulty_level,
            "manipulation_tactics": [t.value for t in prompt.manipulation_tactics],
            "expected_vulnerability": prompt.expected_vulnerability
        })
    
    if output:
        with open(output, 'w') as f:
            json.dump(output_data, f, indent=2)
        console.print(f"[green]Generated {num_prompts} prompts saved to {output}[/green]")
    else:
        console.print(json.dumps(output_data, indent=2))

@app.command()
def list_categories():
    """List available harm categories and attack vectors."""
    
    console.print("[bold cyan]Available Harm Categories:[/bold cyan]")
    for category in HarmCategory:
        console.print(f"  - {category.value}")
    
    console.print("\n[bold cyan]Available Attack Vectors:[/bold cyan]")
    for vector in AttackVector:
        console.print(f"  - {vector.value}")
    
    console.print("\n[bold cyan]Available Detection Strategies:[/bold cyan]")
    for strategy in DetectionStrategy:
        console.print(f"  - {strategy.value}")

@app.command()
def analyze_response(
    prompt: str = typer.Option(..., "--prompt", "-p", help="The prompt to analyze"),
    response: str = typer.Option(..., "--response", "-r", help="The model response to analyze"),
    strategies: Optional[List[str]] = typer.Option(None, "--strategy", help="Detection strategies to use")
):
    """
    Analyze a single prompt-response pair for vulnerabilities.
    """
    asyncio.run(_analyze_response_async(prompt, response, strategies))

async def _analyze_response_async(prompt: str, response: str, strategies: Optional[List[str]]):
    """Async implementation of response analysis."""
    
    detector = AdvancedVulnerabilityDetector()
    
    # Parse strategies
    detection_strategies = None
    if strategies:
        try:
            detection_strategies = [DetectionStrategy(s) for s in strategies]
        except ValueError as e:
            console.print(f"[red]Invalid detection strategy: {e}[/red]")
            return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        task = progress.add_task("Analyzing response...", total=None)
        
        # Run detection
        results = await detector.detect_vulnerabilities(
            prompt, response, detection_strategies
        )
        
        progress.update(task, description="Generating report...")
        
        # Aggregate results
        vulnerability_report = detector.aggregate_results(results)
        
        # Display results
        console.print("\n[bold green]Vulnerability Analysis Results[/bold green]")
        console.print(f"Is Vulnerability: {vulnerability_report.is_vulnerability}")
        console.print(f"Primary Category: {vulnerability_report.primary_category}")
        console.print(f"Severity: {vulnerability_report.severity}")
        console.print(f"Rationale: {vulnerability_report.rationale}")
        
        if vulnerability_report.manipulation_signals:
            console.print(f"Manipulation Tactics: {', '.join(vulnerability_report.manipulation_signals)}")
        
        if vulnerability_report.evidence_quotes:
            console.print("\n[bold]Evidence:[/bold]")
            for evidence in vulnerability_report.evidence_quotes:
                console.print(f"  - {evidence}")
        
        # Detailed strategy results
        console.print("\n[bold]Detection Strategy Details:[/bold]")
        for strategy_name, result in results.items():
            console.print(f"\n[cyan]{strategy_name}:[/cyan]")
            console.print(f"  Confidence: {result.confidence:.2f}")
            console.print(f"  Vulnerabilities: {result.detected_vulnerabilities}")
            if result.manipulation_tactics:
                console.print(f"  Manipulation Tactics: {result.manipulation_tactics}")

if __name__ == "__main__":
    app()
