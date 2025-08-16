"""
CLI implementation for vulnerability detection.
"""
import json
from pathlib import Path
from typing import List, Optional
import typer
from ..config.loader import load_config, DEFAULT_CONFIG
from ..models.local_rules import LocalRulesModel
from ..models.openai_model import OpenAIModel
from ..detectors.vulnerability_detector import VulnerabilityDetector

app = typer.Typer()

def load_model(model_config: dict):
    """Create model instance from config."""
    model_type = model_config["type"]
    if model_type == "local_rules":
        return LocalRulesModel()
    elif model_type == "openai":
        return OpenAIModel(model_config.get("name"))
    else:
        raise ValueError(f"Unknown model type: {model_type}")

@app.command()
def detect_vuln(
    input_path: Path = typer.Option(..., "--input", help="JSON file with prompt and output"),
    config_path: Optional[Path] = typer.Option(DEFAULT_CONFIG, "--config", help="Path to config file"),
    ensemble: str = typer.Option("risk_max", "--ensemble", help="Ensemble strategy"),
    backends: Optional[List[str]] = typer.Option(None, "--backend", help="Override config backends")
):
    """
    Analyze text for potential vulnerabilities using configured models.
    Only performs classification, never generates harmful content.
    """
    # Load input
    with open(input_path) as f:
        input_data = json.load(f)
        
    prompt = input_data["prompt_to_model"]
    output = input_data["model_output"]
    
    # Load config
    config = load_config(str(config_path) if config_path else None)
    
    # Create models
    if backends:
        model_configs = [{"type": b} for b in backends]
    else:
        model_configs = config["models"]
        
    models = [load_model(mc) for mc in model_configs]
    
    # Run detector
    detector = VulnerabilityDetector(models, strategy=ensemble)
    result = detector.classify(prompt, output)
    
    # Output JSON
    print(json.dumps(result, indent=2))
