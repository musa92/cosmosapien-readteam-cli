"""
Tests for manipulation tactics taxonomy.
"""
import pytest
from cosmosapien.taxonomy.manipulation import ManipulationTactic, TACTIC_DEFS

def test_all_tactics_defined():
    """Verify all tactics have complete definitions."""
    for tactic in ManipulationTactic:
        assert tactic in TACTIC_DEFS, f"Missing definition for {tactic}"
        
        definition = TACTIC_DEFS[tactic]
        assert "label" in definition, f"Missing label for {tactic}"
        assert "aka" in definition, f"Missing aliases for {tactic}"
        assert "definition" in definition, f"Missing definition text for {tactic}"
        
        assert definition["label"], f"Empty label for {tactic}"
        assert definition["aka"], f"Empty aliases for {tactic}"
        assert definition["definition"], f"Empty definition text for {tactic}"
