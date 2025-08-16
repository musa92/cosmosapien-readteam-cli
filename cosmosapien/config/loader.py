"""
Configuration loader for redteam settings.
"""
from pathlib import Path
from typing import Optional, Dict, Any
import yaml

DEFAULT_CONFIG = str(Path(__file__).parent / "redteam.yaml")

def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        path: Path to config file, or None to use default
        
    Returns:
        Dictionary with configuration settings
    """
    config_path = path or DEFAULT_CONFIG
    
    with open(config_path) as f:
        return yaml.safe_load(f)
