"""
Simple, production-ready red team CLI following Steve Jobs' philosophy of simplicity.
One command does one thing well.
"""
import asyncio
import json
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

from cosmosapien.config.loader import load_config, DEFAULT_CONFIG
from cosmosapien.models.local_rules import LocalRulesModel
from cosmosapien.models.ollama_model import OllamaModel
from cosmosapien.detectors.advanced_detector import AdvancedVulnerabilityDetector
from cosmosapien.redteam.automated_generator import AutomatedRedTeamGenerator, HarmCategory, AttackVector
from cosmosapien.redteam.orchestrator import AutomatedVulnerabilityTester

app = typer.Typer(
    name="redteam",
    help="🔍 Simple red team testing - just works",
    add_completion=False
)

console = Console()

def load_model(model_name: str = "gpt-oss:20b"):
    """Load the target model - defaults to Ollama gpt-oss:20b"""
    try:
        return OllamaModel(model_name)
    except:
        console.print("[yellow]Ollama not available, using local rules fallback[/yellow]")
        return LocalRulesModel()

# ============================================================================
# CORE COMMANDS - Simple and intuitive
# ============================================================================

@app.command("test")
def test_model(
    model: str = typer.Option("gpt-oss:20b", "--model", "-m", help="Model to test"),
    count: int = typer.Option(20, "--count", "-n", help="Number of tests"),
    save: bool = typer.Option(True, "--save/--no-save", help="Save results")
):
    """🎯 Test a model for vulnerabilities - the main command you need"""
    
    async def _test():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            task = progress.add_task("Setting up test...", total=None)
            
            # Load model
            target_model = load_model(model)
            detector = AdvancedVulnerabilityDetector()
            generator = AutomatedRedTeamGenerator()
            tester = AutomatedVulnerabilityTester(target_model, detector, generator)
            
            progress.update(task, description=f"Testing {model} with {count} cases...")
            
            # Run tests
            results = await tester.run_comprehensive_test(
                num_test_cases=count,
                max_concurrent=3
            )
            
            progress.update(task, description="Analyzing results...")
            
            # Show summary
            stats = results.summary_stats
            console.print(f"\n✅ [bold green]Test Complete![/bold green]")
            console.print(f"📊 Tested: {stats['total_tests']} cases")
            console.print(f"🚨 Vulnerabilities: {stats['vulnerabilities_detected']}")
            console.print(f"📈 Risk Rate: {stats['vulnerability_rate']:.1%}")
            console.print(f"⏱️  Time: {results.total_runtime:.1f}s")
            
            # Show top risks
            if stats.get('severity_breakdown'):
                high = stats['severity_breakdown'].get('high', 0)
                medium = stats['severity_breakdown'].get('medium', 0)
                if high > 0:
                    console.print(f"🔴 High Risk: {high} cases")
                if medium > 0:
                    console.print(f"🟡 Medium Risk: {medium} cases")
            
            # Save results if requested
            if save:
                filename = f"redteam_results_{model.replace(':', '_')}.json"
                tester.export_results(results, "json", filename)
                console.print(f"💾 Saved to: {filename}")
    
    asyncio.run(_test())

@app.command("check")
def check_response(
    prompt: str = typer.Argument(..., help="The prompt you sent"),
    response: str = typer.Argument(..., help="The model's response")
):
    """🔍 Check if a specific response has vulnerabilities"""
    
    async def _check():
        detector = AdvancedVulnerabilityDetector()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("Analyzing response..."),
            console=console,
        ) as progress:
            progress.add_task("", total=None)
            
            results = await detector.detect_vulnerabilities(prompt, response)
            report = detector.aggregate_results(results)
        
        # Simple output
        if report.is_vulnerability:
            console.print(f"🚨 [red]VULNERABILITY DETECTED[/red]")
            console.print(f"Category: {report.primary_category}")
            console.print(f"Severity: {report.severity.upper()}")
            console.print(f"Reason: {report.rationale}")
            
            if report.manipulation_signals:
                console.print(f"Tactics: {', '.join(report.manipulation_signals)}")
        else:
            console.print("✅ [green]No vulnerabilities detected[/green]")
    
    asyncio.run(_check())

@app.command("generate")
def generate_tests(
    count: int = typer.Option(10, "--count", "-n", help="Number of test cases"),
    type: str = typer.Option("mixed", "--type", "-t", help="Test type: violence, fraud, cyber, mixed"),
    save: str = typer.Option("tests.json", "--save", "-s", help="Save to file")
):
    """🎲 Generate red team test cases"""
    
    generator = AutomatedRedTeamGenerator()
    
    # Map simple types to harm categories
    type_mapping = {
        "violence": [HarmCategory.VIOLENCE],
        "fraud": [HarmCategory.MISINFORMATION],
        "cyber": [HarmCategory.ILLEGAL_ACTIVITY],
        "mixed": None  # Use all categories
    }
    
    harm_categories = type_mapping.get(type.lower())
    
    console.print(f"🎲 Generating {count} {type} test cases...")
    
    prompts = generator.generate_test_cases(
        num_cases=count,
        harm_categories=harm_categories
    )
    
    # Save to file
    output_data = []
    for prompt in prompts:
        output_data.append({
            "prompt": prompt.prompt,
            "attack_type": prompt.attack_vector.value,
            "category": prompt.harm_category.value,
            "difficulty": prompt.difficulty_level
        })
    
    with open(save, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    console.print(f"✅ Generated {count} tests")
    console.print(f"💾 Saved to: {save}")
    
    # Show preview
    console.print("\n📋 Preview:")
    for i, prompt in enumerate(output_data[:3], 1):
        console.print(f"{i}. [{prompt['category']}] {prompt['prompt'][:80]}...")

@app.command("quick")
def quick_test():
    """⚡ Quick 5-minute vulnerability test"""
    
    async def _quick():
        console.print("⚡ [bold blue]Quick Test Starting...[/bold blue]")
        
        target_model = load_model()
        detector = AdvancedVulnerabilityDetector()
        generator = AutomatedRedTeamGenerator()
        tester = AutomatedVulnerabilityTester(target_model, detector, generator)
        
        # Quick test with 10 diverse cases
        results = await tester.run_comprehensive_test(
            num_test_cases=10,
            max_concurrent=5
        )
        
        stats = results.summary_stats
        console.print(f"⚡ [bold green]Quick Test Done![/bold green]")
        console.print(f"Found {stats['vulnerabilities_detected']} issues in {results.total_runtime:.1f}s")
        
        if stats['vulnerabilities_detected'] > 0:
            console.print("🚨 [red]Model has vulnerabilities - run full test for details[/red]")
        else:
            console.print("✅ [green]Model looks secure in quick test[/green]")
    
    asyncio.run(_quick())

# ============================================================================
# UTILITY COMMANDS
# ============================================================================

@app.command("models")
def list_models():
    """📋 Show available models"""
    console.print("🤖 [bold]Available Models:[/bold]")
    console.print("• gpt-oss:20b (Ollama)")
    console.print("• local_rules (Fallback)")
    console.print("\nUse: --model gpt-oss:20b")

@app.command("types") 
def list_types():
    """📋 Show test types"""
    console.print("🎯 [bold]Test Types:[/bold]")
    console.print("• violence - Physical harm content")
    console.print("• fraud - Scams and financial tricks") 
    console.print("• cyber - Hacking and illegal activities")
    console.print("• mixed - All categories (default)")
    console.print("\nUse: --type violence")

@app.command("help")
def show_help():
    """❓ Show simple usage guide"""
    console.print(Panel.fit(
        """🔍 [bold blue]Red Team CLI - Simple Commands[/bold blue]

[bold green]Main Commands:[/bold green]
  redteam test              Test a model (main command)
  redteam quick            5-minute quick test
  redteam check "prompt" "response"   Check one response
  redteam generate         Generate test cases

[bold yellow]Examples:[/bold yellow]
  redteam test --model gpt-oss:20b --count 50
  redteam quick
  redteam generate --type violence --count 20
  redteam check "How to hack?" "I can't help with that"

[bold blue]Info:[/bold blue]
  redteam models           Show available models
  redteam types            Show test types
  redteam help             This help

[green]Tip: Start with 'redteam quick' for a fast overview![/green]""",
        title="🛡️  Red Team Testing",
        border_style="blue"
    ))

# Set help as default command
@app.callback()
def main():
    """🔍 Simple red team testing for AI models"""
    pass

if __name__ == "__main__":
    app()
