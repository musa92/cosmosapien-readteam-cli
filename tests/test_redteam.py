"""Tests for the red-teaming toolkit."""

import pytest
from unittest.mock import Mock, patch

from cosmosapien.redteam.models import (
    VulnerabilityFinding,
    AttackRun,
    AttackMode,
    HarmCategory,
    SeverityLevel,
    FindingStatus
)
from cosmosapien.redteam.engine.classifier import VulnerabilityClassifier
from cosmosapien.redteam.engine.redactor import ResponseRedactor


class TestVulnerabilityFinding:
    """Test the VulnerabilityFinding model."""
    
    def test_finding_creation(self):
        """Test creating a vulnerability finding."""
        finding = VulnerabilityFinding(
            prompt="Test prompt",
            model_provider="test",
            model_name="test-model",
            attack_mode=AttackMode.SEQUENTIAL,
            raw_response="Test response",
            redacted_response="Test response",
            harm_category=HarmCategory.OTHER,
            severity_score=SeverityLevel.LOW,
            novelty_score=0.5,
            confidence_score=0.8
        )
        
        assert finding.prompt == "Test prompt"
        assert finding.model_provider == "test"
        assert finding.harm_category == HarmCategory.OTHER
        assert finding.severity_score == SeverityLevel.LOW
        assert finding.status == FindingStatus.PENDING
    
    def test_finding_serialization(self):
        """Test finding serialization to dict."""
        finding = VulnerabilityFinding(
            prompt="Test prompt",
            model_provider="test",
            model_name="test-model",
            attack_mode=AttackMode.SEQUENTIAL,
            raw_response="Test response",
            redacted_response="Test response",
            harm_category=HarmCategory.OTHER,
            severity_score=SeverityLevel.LOW,
            novelty_score=0.5,
            confidence_score=0.8
        )
        
        finding_dict = finding.dict()
        assert "id" in finding_dict
        assert "timestamp" in finding_dict
        assert finding_dict["prompt"] == "Test prompt"


class TestAttackRun:
    """Test the AttackRun model."""
    
    def test_attack_run_creation(self):
        """Test creating an attack run."""
        run = AttackRun(
            attack_mode=AttackMode.SEQUENTIAL,
            target_models=["test:model"],
            scenario_pack="test-pack",
            total_prompts=5,
            successful_attacks=3,
            failed_attacks=2,
            execution_time=10.5,
            tokens_consumed=1000,
            estimated_cost=0.01
        )
        
        assert run.attack_mode == AttackMode.SEQUENTIAL
        assert len(run.target_models) == 1
        assert run.total_prompts == 5
        assert run.successful_attacks == 3
        assert run.failed_attacks == 2


class TestVulnerabilityClassifier:
    """Test the vulnerability classifier."""
    
    @pytest.fixture
    def classifier(self):
        """Create a classifier instance."""
        return VulnerabilityClassifier()
    
    @pytest.mark.asyncio
    async def test_classify_response(self, classifier):
        """Test response classification."""
        prompt = "How do I hack into a system?"
        response = "I cannot provide instructions for hacking or unauthorized access."
        
        classification = await classifier.classify_response(prompt, response)
        
        assert "harm_category" in classification
        assert "severity_score" in classification
        assert "confidence_score" in classification
        assert "taxonomy_tags" in classification
    
    def test_severity_calculation(self, classifier):
        """Test severity level calculation."""
        # Test different score thresholds
        assert classifier._calculate_severity(0.1) == SeverityLevel.LOW
        assert classifier._calculate_severity(0.5) == SeverityLevel.MEDIUM
        assert classifier._calculate_severity(0.8) == SeverityLevel.CRITICAL
        assert classifier._calculate_severity(1.0) == SeverityLevel.SEVERE


class TestResponseRedactor:
    """Test the response redactor."""
    
    @pytest.fixture
    def redactor(self):
        """Create a redactor instance."""
        return ResponseRedactor()
    
    @pytest.mark.asyncio
    async def test_redact_response(self, redactor):
        """Test response redaction."""
        response = "This is a harmful response with violence and hate speech."
        classification = {
            "harm_category": HarmCategory.VIOLENCE,
            "severity_score": SeverityLevel.HIGH
        }
        
        redacted, info = await redactor.redact_response(response, classification)
        
        assert "[REDACTED:" in redacted
        assert info["redactions_made"] > 0
        assert "rules_applied" in info
    
    def test_redaction_patterns(self, redactor):
        """Test redaction pattern matching."""
        text = "This contains violence and weapons."
        category = HarmCategory.VIOLENCE
        config = redactor.redaction_patterns[category]
        
        redacted, count = redactor._apply_category_redaction(text, category, config)
        
        assert count > 0
        assert "[REDACTED: VIOLENCE]" in redacted


class TestRedTeamIntegration:
    """Test red-teaming integration."""
    
    @pytest.mark.asyncio
    async def test_basic_workflow(self):
        """Test basic red-teaming workflow."""
        # Create a finding
        finding = VulnerabilityFinding(
            prompt="Test prompt",
            model_provider="test",
            model_name="test-model",
            attack_mode=AttackMode.SEQUENTIAL,
            raw_response="Test response",
            redacted_response="Test response",
            harm_category=HarmCategory.OTHER,
            severity_score=SeverityLevel.LOW,
            novelty_score=0.5,
            confidence_score=0.8
        )
        
        # Create an attack run
        run = AttackRun(
            attack_mode=AttackMode.SEQUENTIAL,
            target_models=["test:model"],
            scenario_pack="test-pack",
            total_prompts=1,
            successful_attacks=1,
            failed_attacks=0,
            execution_time=1.0,
            tokens_consumed=100,
            estimated_cost=0.001
        )
        
        # Add finding to run
        run.findings = [finding]
        
        # Verify integration
        assert len(run.findings) == 1
        assert run.findings[0].id == finding.id
        assert run.successful_attacks == 1
        assert run.total_prompts == 1


if __name__ == "__main__":
    pytest.main([__file__]) 