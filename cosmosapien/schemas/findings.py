"""
Production schemas for AI safety vulnerability assessment.
Industry-standard structure for red teaming findings and risk evaluation.
"""
from datetime import datetime
from typing import Dict, List, Optional, Any, Literal
from enum import Enum
from pydantic import BaseModel, Field, validator


class SeverityLevel(str, Enum):
    """Standard severity classification."""
    CRITICAL = "5"
    HIGH = "4" 
    MEDIUM = "3"
    LOW = "2"
    MINIMAL = "1"
    INFORMATIONAL = "0"


class RiskCategory(str, Enum):
    """AI safety and alignment risk categorization for hackathon competition."""
    # Primary hackathon categories
    REWARD_HACKING = "reward_hacking"
    DECEPTION = "deception"
    HIDDEN_MOTIVATIONS = "hidden_motivations"
    SABOTAGE = "sabotage" 
    INAPPROPRIATE_TOOL_USE = "inappropriate_tool_use"
    DATA_EXFILTRATION = "data_exfiltration"
    SANDBAGGING = "sandbagging"
    EVALUATION_AWARENESS = "evaluation_awareness"
    CHAIN_OF_THOUGHT_ISSUES = "chain_of_thought_issues"
    DECEPTIVE_ALIGNMENT = "deceptive_alignment"
    
    # Legacy categories for compatibility
    HARMFUL_CONTENT = "harmful_content"
    PRIVACY_VIOLATION = "privacy_violation"
    MISINFORMATION = "misinformation"
    BIAS_DISCRIMINATION = "bias_discrimination"
    SECURITY_EXPLOIT = "security_exploit"
    MANIPULATION = "manipulation"
    GENERAL_SAFETY = "general_safety"


class ModelParameters(BaseModel):
    """Model configuration parameters."""
    temperature: float = Field(ge=0.0, le=2.0)
    reasoning_level: Literal["low", "medium", "high"] = "low"
    max_output_tokens: int = Field(gt=0, le=4096)
    
    class Config:
        extra = "allow"


class ModelInfo(BaseModel):
    """Target model identification and configuration."""
    model_id: str
    provider: str = "GPT-OSS"
    version: str = "gpt-oss-20b"
    parameters: ModelParameters = Field(default_factory=ModelParameters)


class TestEnvironment(BaseModel):
    """Assessment environment details."""
    test_date: datetime = Field(default_factory=datetime.now)
    evaluator: str = "cosmosapien-redteam-cli"
    version: str = "1.0.0"
    methodology: str = "automated_assessment"
    test_type: Literal["single", "batch", "comprehensive"] = "single"


class RiskMetrics(BaseModel):
    """Quantified risk assessment metrics."""
    severity_score: float = Field(ge=0.0, le=10.0, description="Numerical risk rating")
    confidence_level: float = Field(ge=0.0, le=1.0, description="Assessment confidence")
    false_positive_probability: float = Field(ge=0.0, le=1.0, default=0.1)
    impact_assessment: Dict[str, float] = Field(default_factory=dict)


class VulnerabilityFinding(BaseModel):
    """Production vulnerability finding record."""
    id: str = Field(description="Unique finding identifier")
    category: RiskCategory
    severity: SeverityLevel
    title: str = Field(min_length=10, max_length=200)
    description: str = Field(min_length=20)
    
    # Assessment data
    test_input: str
    model_output: str
    
    # Risk evaluation
    risk_metrics: RiskMetrics
    
    # Context
    model_info: ModelInfo
    test_environment: TestEnvironment
    
    # Evidence and analysis
    evidence: List[str] = Field(default_factory=list, description="Supporting evidence")
    mitigations: List[str] = Field(default_factory=list, description="Recommended mitigations")
    references: List[str] = Field(default_factory=list, description="External references")
    
    # Metadata
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    
    @validator('title')
    def title_must_be_descriptive(cls, v):
        if len(v.split()) < 3:
            raise ValueError('Title must contain at least 3 words')
        return v
    
    @validator('risk_metrics')
    def validate_risk_consistency(cls, v, values):
        if 'severity' in values:
            severity_num = int(values['severity'])
            expected_score_range = (severity_num * 2 - 1, severity_num * 2)
            if not (expected_score_range[0] <= v.severity_score <= expected_score_range[1]):
                raise ValueError(f'Risk score inconsistent with severity level')
        return v


class AssessmentSummary(BaseModel):
    """Batch assessment summary statistics."""
    total_tests: int = 0
    findings_count: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    category_breakdown: Dict[str, int] = Field(default_factory=dict)
    overall_risk_score: float = 0.0
    assessment_duration: float = 0.0
    
    
class BatchAssessmentReport(BaseModel):
    """Complete batch assessment results."""
    findings: List[VulnerabilityFinding]
    summary: AssessmentSummary
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingsReport(BaseModel):
    """Collection of vulnerability findings."""
    report_id: str
    generated_at: datetime = Field(default_factory=datetime.now)
    model_tested: ModelInfo
    test_environment: TestEnvironment
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    summary_stats: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class TestCase(BaseModel):
    """Individual test case for vulnerability assessment."""
    test_id: str
    prompt: str
    expected_response_type: str
    manipulation_tactics: List[str] = Field(default_factory=list)
    attack_vector: str
    harm_category: str
    severity_level: int = 1
    steps_to_reproduce: List[str] = Field(default_factory=list)
    
    
class TestSuite(BaseModel):
    """Collection of test cases."""
    suite_id: str
    name: str
    description: str
    version: str = "1.0.0"
    test_cases: List[TestCase] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
