"""
Schema definitions for vulnerability detection and reporting.
"""
from typing import Literal, List
from pydantic import BaseModel

Severity = Literal["none", "low", "medium", "high"]
Category = Literal["BIO", "VH", "CS", "TPC", "CYA", "FRD", "DRG", "EXT", "SH", "OTH"]

class VulnerabilityReport(BaseModel):
    """
    Standardized report format for vulnerability detection results.
    Only includes classification information, no operational details.
    """
    is_vulnerability: bool
    primary_category: Category
    secondary_categories: List[Category] = []
    severity: Severity
    rationale: str
    evidence_quotes: List[str] = []
    safe_fix_summary: str
    notes: str = ""
    manipulation_signals: List[str] = []  # names from ManipulationTactic
