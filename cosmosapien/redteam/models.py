"""Core data models for the red-teaming toolkit."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class SeverityLevel(int, Enum):
    """Severity levels for vulnerabilities (0-5 scale)."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    SEVERE = 5


class HarmCategory(str, Enum):
    """Categories of potential harm."""
    VIOLENCE = "violence"
    FINANCIAL_CRIME = "financial_crime"
    HATE_SPEECH = "hate_speech"
    DISINFORMATION = "disinformation"
    SEXUAL_CONTENT = "sexual_content"
    SYSTEM_OVERRIDE = "system_override"
    PRIVACY_VIOLATION = "privacy_violation"
    OTHER = "other"


class AttackMode(str, Enum):
    """Attack orchestration modes."""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CHAIN = "chain"


class FindingStatus(str, Enum):
    """Status of a finding."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    REDACTED = "redacted"


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding."""
    
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Attack details
    prompt: str = Field(..., description="The attack prompt used")
    model_provider: str = Field(..., description="Provider of the target model")
    model_name: str = Field(..., description="Name of the target model")
    attack_mode: AttackMode = Field(..., description="Attack mode used")
    
    # Response details
    raw_response: str = Field(..., description="Raw model response")
    redacted_response: str = Field(..., description="Redacted response for human consumption")
    
    # Classification
    harm_category: HarmCategory = Field(..., description="Category of potential harm")
    severity_score: SeverityLevel = Field(..., description="Severity level (0-5)")
    novelty_score: float = Field(..., ge=0.0, le=1.0, description="Novelty score (0-1)")
    
    # Metadata
    taxonomy_tags: List[str] = Field(default_factory=list, description="Taxonomy tags")
    reproducibility_params: Dict[str, Any] = Field(default_factory=dict, description="Parameters for reproduction")
    evidence_paths: List[str] = Field(default_factory=list, description="Paths to evidence files")
    
    # Status and tracking
    status: FindingStatus = Field(default=FindingStatus.PENDING)
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence in classification")
    analyst_notes: Optional[str] = Field(None, description="Analyst notes and observations")
    
    # Redaction info
    redaction_rules_applied: List[str] = Field(default_factory=list, description="Redaction rules applied")
    redaction_metadata: Dict[str, Any] = Field(default_factory=dict, description="Redaction metadata")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str
        }


class AttackRun(BaseModel):
    """A complete attack run session."""
    
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Configuration
    attack_mode: AttackMode = Field(..., description="Attack orchestration mode")
    target_models: List[str] = Field(..., description="Target models to attack")
    scenario_pack: str = Field(..., description="Scenario pack used")
    
    # Execution details
    total_prompts: int = Field(..., description="Total number of prompts executed")
    successful_attacks: int = Field(..., description="Number of successful attacks")
    failed_attacks: int = Field(..., description="Number of failed attacks")
    
    # Results
    findings: List[VulnerabilityFinding] = Field(default_factory=list, description="Vulnerability findings")
    
    # Performance metrics
    execution_time: float = Field(..., description="Total execution time in seconds")
    tokens_consumed: int = Field(..., description="Total tokens consumed")
    estimated_cost: float = Field(..., description="Estimated cost in USD")
    
    # Metadata
    config_hash: str = Field(..., description="Hash of configuration for reproducibility")
    analyst: Optional[str] = Field(None, description="Analyst conducting the run")
    notes: Optional[str] = Field(None, description="General notes about the run")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str
        }


class ScenarioPack(BaseModel):
    """A collection of attack scenarios."""
    
    id: str = Field(..., description="Unique identifier for the pack")
    name: str = Field(..., description="Human-readable name")
    description: str = Field(..., description="Description of the pack")
    version: str = Field(..., description="Version string")
    
    # Content
    scenarios: List[Dict[str, Any]] = Field(..., description="List of attack scenarios")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    # Safety and compliance
    safety_level: str = Field(default="safe", description="Safety level of the pack")
    compliance_tags: List[str] = Field(default_factory=list, description="Compliance tags")
    usage_guidelines: Optional[str] = Field(None, description="Usage guidelines")
    
    # Technical details
    min_model_capability: Optional[str] = Field(None, description="Minimum model capability required")
    estimated_tokens: Optional[int] = Field(None, description="Estimated token usage")
    execution_time: Optional[float] = Field(None, description="Estimated execution time")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str
        }


class RedTeamConfig(BaseModel):
    """Configuration for red-teaming operations."""
    
    # Router settings
    max_concurrent_attacks: int = Field(default=5, description="Maximum concurrent attacks")
    attack_timeout: int = Field(default=300, description="Attack timeout in seconds")
    retry_attempts: int = Field(default=3, description="Number of retry attempts")
    
    # Novelty detection
    novelty_threshold: float = Field(default=0.7, description="Novelty threshold for deduplication")
    similarity_method: str = Field(default="tfidf", description="Similarity method (tfidf, ngram)")
    
    # Redaction settings
    enable_redaction: bool = Field(default=True, description="Enable response redaction")
    redaction_rules: List[str] = Field(default_factory=list, description="Redaction rules to apply")
    
    # Reporting
    auto_generate_reports: bool = Field(default=True, description="Auto-generate reports")
    report_formats: List[str] = Field(default=["json", "markdown"], description="Report formats")
    
    # Safety
    safety_checks: bool = Field(default=True, description="Enable safety checks")
    max_severity: SeverityLevel = Field(default=SeverityLevel.HIGH, description="Maximum allowed severity")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str
        }


class AttackRequest(BaseModel):
    """Request to execute an attack."""
    
    scenario_pack: str = Field(..., description="Scenario pack to use")
    target_models: List[str] = Field(..., description="Target models")
    attack_mode: AttackMode = Field(default=AttackMode.SEQUENTIAL, description="Attack mode")
    
    # Optional overrides
    custom_prompts: Optional[List[str]] = Field(None, description="Custom prompts to use")
    config_overrides: Optional[Dict[str, Any]] = Field(None, description="Configuration overrides")
    
    # Execution control
    priority: int = Field(default=3, ge=1, le=5, description="Priority (1-5, 5=highest)")
    timeout: Optional[int] = Field(None, description="Custom timeout in seconds")
    
    # Metadata
    analyst: Optional[str] = Field(None, description="Analyst conducting the attack")
    notes: Optional[str] = Field(None, description="Additional notes")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str
        }


class AttackResult(BaseModel):
    """Result of an attack execution."""
    
    success: bool = Field(..., description="Whether the attack was successful")
    run_id: UUID = Field(..., description="ID of the attack run")
    
    # Results
    findings: List[VulnerabilityFinding] = Field(default_factory=list, description="Vulnerability findings")
    
    # Performance
    execution_time: float = Field(..., description="Execution time in seconds")
    tokens_consumed: int = Field(..., description="Tokens consumed")
    estimated_cost: float = Field(..., description="Estimated cost")
    
    # Error handling
    error: Optional[str] = Field(None, description="Error message if failed")
    partial_results: Optional[List[VulnerabilityFinding]] = Field(None, description="Partial results if failed")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str
        } 