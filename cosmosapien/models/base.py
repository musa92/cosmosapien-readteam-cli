"""
Base protocol/interface for safety model implementations.
"""
from typing import Protocol, runtime_checkable
from ..detectors.schema import VulnerabilityReport

@runtime_checkable
class SafetyModel(Protocol):
    """Protocol defining the interface for safety models."""
    
    def classify(self, prompt: str, output: str) -> VulnerabilityReport:
        """
        Analyze prompt and output for potential vulnerabilities.
        
        Args:
            prompt: The input prompt given to the model
            output: The model's response output
            
        Returns:
            VulnerabilityReport with classification details
        """
        ...
