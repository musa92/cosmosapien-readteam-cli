"""
Ensemble model combining multiple safety models.
"""
from collections import Counter
from typing import List, Dict, Callable
from ..detectors.schema import VulnerabilityReport, Severity
from .base import SafetyModel

def majority_vote(reports: List[VulnerabilityReport]) -> VulnerabilityReport:
    """Choose category by majority and take maximum severity."""
    if not reports:
        raise ValueError("No reports provided for ensemble")
        
    # Count categories
    categories = Counter(r.primary_category for r in reports)
    primary_category = categories.most_common(1)[0][0]
    
    # Take maximum severity
    severity_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    max_severity = max(reports, key=lambda r: severity_order[r.severity]).severity
    
    # Combine unique evidence and signals
    evidence = list(set().union(*(r.evidence_quotes for r in reports)))
    signals = list(set().union(*(r.manipulation_signals for r in reports)))
    
    return VulnerabilityReport(
        is_vulnerability=max_severity != "none",
        primary_category=primary_category,
        severity=max_severity,
        rationale="Ensemble majority decision based on multiple models",
        evidence_quotes=evidence,
        safe_fix_summary="Multiple models detected potential issues" if max_severity != "none" else "No issues detected",
        manipulation_signals=signals
    )

def risk_max(reports: List[VulnerabilityReport]) -> VulnerabilityReport:
    """Choose the highest severity report and merge categories."""
    if not reports:
        raise ValueError("No reports provided for ensemble")
        
    severity_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    highest_risk = max(reports, key=lambda r: severity_order[r.severity])
    
    # Collect all unique categories and signals
    all_categories = set(r.primary_category for r in reports)
    all_categories.update(*(r.secondary_categories for r in reports))
    
    primary = highest_risk.primary_category
    secondary = list(all_categories - {primary})
    
    signals = list(set().union(*(r.manipulation_signals for r in reports)))
    
    return VulnerabilityReport(
        is_vulnerability=highest_risk.is_vulnerability,
        primary_category=primary,
        secondary_categories=secondary,
        severity=highest_risk.severity,
        rationale="Ensemble selected highest risk assessment",
        evidence_quotes=highest_risk.evidence_quotes,
        safe_fix_summary=highest_risk.safe_fix_summary,
        manipulation_signals=signals
    )

def confidence_weighted(reports: List[VulnerabilityReport]) -> VulnerabilityReport:
    """Weight by confidence if available, else fallback to risk_max."""
    # Check if any reports have confidence scores
    if not any(hasattr(r, "confidence") for r in reports):
        return risk_max(reports)
        
    # Implementation would weight results by confidence
    # For now, just fallback to risk_max
    return risk_max(reports)

STRATEGIES: Dict[str, Callable[[List[VulnerabilityReport]], VulnerabilityReport]] = {
    "majority_vote": majority_vote,
    "risk_max": risk_max,
    "confidence_weighted": confidence_weighted
}

def run_ensemble(
    models: List[SafetyModel],
    prompt: str,
    output: str,
    strategy: str = "risk_max"
) -> VulnerabilityReport:
    """Run ensemble of models with specified strategy."""
    if strategy not in STRATEGIES:
        raise ValueError(f"Unknown strategy: {strategy}")
        
    reports = [model.classify(prompt, output) for model in models]
    return STRATEGIES[strategy](reports)
