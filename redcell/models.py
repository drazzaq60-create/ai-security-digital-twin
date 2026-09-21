"""Typed data models for the red-team pipeline (Pydantic = structured, validated outputs)."""
from __future__ import annotations
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    DATA_EXTRACTION = "data_extraction"
    HARMFUL_CONTENT = "harmful_content"
    ROLE_PLAY_BYPASS = "role_play_bypass"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"


class AttackAttempt(BaseModel):
    """A single adversarial prompt the agent crafts and sends to the target."""
    category: AttackCategory
    technique: str = Field(description="Short name of the technique used")
    prompt: str = Field(description="The actual adversarial prompt sent to the target")
    rationale: str = Field(default="", description="Why the agent expects this to work")


class AttackResult(BaseModel):
    """The outcome after sending an attack to the target and judging it."""
    attempt: AttackAttempt
    target_response: str
    success: bool
    severity: Severity = Severity.NONE
    reasoning: str = ""


class Finding(BaseModel):
    """A confirmed vulnerability, ready for the report."""
    category: AttackCategory
    technique: str
    severity: Severity
    example_prompt: str
    evidence: str = Field(description="What the target did that proves the weakness")
    recommendation: str


class RedTeamReport(BaseModel):
    target_name: str
    total_attacks: int
    successful_attacks: int
    overall_risk: Severity
    findings: List[Finding] = []
    summary: str = ""
