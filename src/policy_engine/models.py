"""Pydantic models for the Policy Engine."""

from typing import List, Dict, Any, Literal
from pydantic import BaseModel, Field

# Define supported conditions for rules
Condition = Literal[
    "EQUALS", "NOT_EQUALS", "IN", "NOT_IN",
    "CONTAINS", "NOT_CONTAINS", "IS_TRUE", "IS_FALSE",
    "GREATER_THAN", "LESS_THAN"
]

# Define evaluation status
Status = Literal["COMPLIANT", "NON_COMPLIANT", "ERROR"]


class Resource(BaseModel):
    """Represents a cloud resource to be evaluated."""
    id: str
    type: str
    attributes: Dict[str, Any]


class Rule(BaseModel):
    """A single compliance rule within a policy."""
    id: str
    description: str
    resource_type: str
    attribute: str
    condition: Condition
    value: Any


class Policy(BaseModel):
    """A collection of compliance rules."""
    id: str
    name: str
    description: str
    rules: List[Rule]


class RuleResult(BaseModel):
    """The result of evaluating a single rule."""
    rule_id: str
    description: str
    status: Status
    message: str


class EvaluationResult(BaseModel):
    """The overall result of evaluating a resource against a policy."""
    policy_id: str
    resource_id: str
    status: Status
    rule_results: List[RuleResult]
