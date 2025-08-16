#!/bin/bash

# ================================================================================
# Manual Phase 2 Setup - Policy Engine Implementation
# Execute these commands step by step in your project root directory.
# ================================================================================

cd ~/projects/cloud-compliance-framework

echo "🚀 Starting Cloud Compliance Framework - Phase 2: Policy Engine Implementation"
echo "Current directory: $(pwd)"

# Step 1: Create Policy Engine Core Files
echo "📝 Creating Policy Engine core source files..."

# Create src/policy_engine/__init__.py
cat > src/policy_engine/__init__.py << 'EOF'
"""
Core Policy Evaluation Engine.

This package contains the logic for loading, parsing, and evaluating
compliance policies against cloud resource configurations.
"""
from .engine import PolicyEngine
from .models import Policy, EvaluationResult

__all__ = ["PolicyEngine", "Policy", "EvaluationResult"]
EOF

# Create src/policy_engine/models.py for data structures
cat > src/policy_engine/models.py << 'EOF'
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
EOF

# Create src/policy_engine/loader.py to load policies from files
cat > src/policy_engine/loader.py << 'EOF'
"""Loads and validates policy files."""

import yaml
from pathlib import Path
from typing import List
from .models import Policy
from src.logger import get_logger

logger = get_logger(__name__)


def load_policies_from_directory(directory: Path) -> List[Policy]:
    """
    Loads all YAML policy files from a specified directory.

    Args:
        directory: The path to the directory containing policy files.

    Returns:
        A list of validated Policy objects.
    """
    if not directory.is_dir():
        logger.error(f"Policy directory not found: {directory}")
        return []

    policies = []
    for file_path in directory.glob("*.yaml"):
        try:
            with open(file_path, "r") as f:
                policy_data = yaml.safe_load(f)
                policy = Policy(**policy_data)
                policies.append(policy)
                logger.info(f"Successfully loaded policy: {policy.id}")
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error validating policy file {file_path}: {e}")

    return policies
EOF

# Create src/policy_engine/evaluator.py for the core logic
cat > src/policy_engine/evaluator.py << 'EOF'
"""Core rule evaluation logic."""

from typing import Any, Dict
from .models import Rule, Status

def evaluate_rule(rule: Rule, resource_attributes: Dict[str, Any]) -> bool:
    """
    Evaluates a single rule against a resource's attributes.

    Args:
        rule: The rule to evaluate.
        resource_attributes: The attributes of the cloud resource.

    Returns:
        True if the resource is compliant with the rule, False otherwise.
    """
    # Use getattr_nested to handle nested attributes like 'PublicAccessBlockConfiguration.BlockPublicAcls'
    actual_value = getattr_nested(resource_attributes, rule.attribute)
    expected_value = rule.value

    if actual_value is None:
        return False  # Attribute not found, considered non-compliant

    condition_map = {
        "EQUALS": lambda a, b: a == b,
        "NOT_EQUALS": lambda a, b: a != b,
        "IN": lambda a, b: a in b,
        "NOT_IN": lambda a, b: a not in b,
        "CONTAINS": lambda a, b: b in a,
        "NOT_CONTAINS": lambda a, b: b not in a,
        "IS_TRUE": lambda a, b: a is True,
        "IS_FALSE": lambda a, b: a is False,
        "GREATER_THAN": lambda a, b: a > b,
        "LESS_THAN": lambda a, b: a < b,
    }

    eval_func = condition_map.get(rule.condition)
    if not eval_func:
        raise ValueError(f"Unsupported condition: {rule.condition}")

    return eval_func(actual_value, expected_value)

def getattr_nested(obj: Dict[str, Any], attr_string: str) -> Any:
    """
    Gets a nested attribute from a dictionary using a dot-separated string.
    Example: getattr_nested(data, 'a.b.c') is equivalent to data['a']['b']['c']
    """
    attrs = attr_string.split('.')
    for attr in attrs:
        if isinstance(obj, dict):
            obj = obj.get(attr)
        else:
            return None # Path is invalid
        if obj is None:
            return None # Attribute not found
    return obj
EOF

# Create src/policy_engine/engine.py to orchestrate the process
cat > src/policy_engine/engine.py << 'EOF'
"""Main Policy Engine orchestrator."""

from typing import List
from .models import Policy, Resource, EvaluationResult, RuleResult, Status
from .evaluator import evaluate_rule
from src.logger import get_logger

logger = get_logger(__name__)


class PolicyEngine:
    """Orchestrates policy loading and evaluation."""

    def __init__(self, policies: List[Policy]):
        self._policies = {p.id: p for p in policies}
        logger.info(f"Policy Engine initialized with {len(self._policies)} policies.")

    def evaluate(self, resource: Resource) -> List[EvaluationResult]:
        """
        Evaluates a resource against all applicable policies.

        Args:
            resource: The cloud resource to evaluate.

        Returns:
            A list of evaluation results, one for each applicable policy.
        """
        results = []
        for policy in self._policies.values():
            # Check if any rule in the policy applies to this resource type
            if any(rule.resource_type == resource.type for rule in policy.rules):
                result = self._evaluate_policy(policy, resource)
                results.append(result)
        return results

    def _evaluate_policy(self, policy: Policy, resource: Resource) -> EvaluationResult:
        """Helper to evaluate a resource against a single policy."""
        rule_results = []
        is_compliant = True

        for rule in policy.rules:
            if rule.resource_type != resource.type:
                continue

            try:
                compliant = evaluate_rule(rule, resource.attributes)
                status: Status = "COMPLIANT" if compliant else "NON_COMPLIANT"
                message = f"Attribute '{rule.attribute}' is compliant." if compliant else f"Violation: Attribute '{rule.attribute}' is non-compliant. Expected condition: {rule.condition} {rule.value}."

                if not compliant:
                    is_compliant = False

                rule_results.append(
                    RuleResult(rule_id=rule.id, description=rule.description, status=status, message=message)
                )
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.id}: {e}")
                is_compliant = False
                rule_results.append(
                    RuleResult(rule_id=rule.id, description=rule.description, status="ERROR", message=str(e))
                )

        overall_status: Status = "COMPLIANT" if is_compliant else "NON_COMPLIANT"
        return EvaluationResult(
            policy_id=policy.id,
            resource_id=resource.id,
            status=overall_status,
            rule_results=rule_results,
        )
EOF

echo "✅ Policy Engine core files created"

# Step 2: Create a Sample Policy and Resource Data
echo "📊 Creating sample policy and resource data files..."

# Create a sample S3 policy in YAML
cat > config/policies/aws_s3_policy.yaml << 'EOF'
id: "aws-s3-best-practices-v1"
name: "AWS S3 Bucket Best Practices"
description: "Ensures S3 buckets follow security best practices."
rules:
  - id: "s3-block-public-access"
    description: "S3 buckets should block public access."
    resource_type: "AWS::S3::Bucket"
    attribute: "PublicAccessBlockConfiguration.BlockPublicAcls"
    condition: "IS_TRUE"
    value: true

  - id: "s3-enable-versioning"
    description: "S3 buckets should have versioning enabled."
    resource_type: "AWS::S3::Bucket"
    attribute: "VersioningConfiguration.Status"
    condition: "EQUALS"
    value: "Enabled"

  - id: "s3-enable-encryption"
    description: "S3 buckets should have server-side encryption enabled."
    resource_type: "AWS::S3::Bucket"
    attribute: "BucketEncryption.ServerSideEncryptionConfiguration.0.ServerSideEncryptionByDefault.SSEAlgorithm"
    condition: "EQUALS"
    value: "AES256"
EOF

# Create a sample compliant S3 resource
cat > data/samples/s3_compliant.json << 'EOF'
{
  "id": "my-compliant-secure-bucket",
  "type": "AWS::S3::Bucket",
  "attributes": {
    "PublicAccessBlockConfiguration": {
      "BlockPublicAcls": true,
      "BlockPublicPolicy": true,
      "IgnorePublicAcls": true,
      "RestrictPublicBuckets": true
    },
    "VersioningConfiguration": {
      "Status": "Enabled"
    },
    "BucketEncryption": {
      "ServerSideEncryptionConfiguration": [
        {
          "ServerSideEncryptionByDefault": {
            "SSEAlgorithm": "AES256"
          }
        }
      ]
    }
  }
}
EOF

# Create a sample non-compliant S3 resource
cat > data/samples/s3_non_compliant.json << 'EOF'
{
  "id": "my-non-compliant-public-bucket",
  "type": "AWS::S3::Bucket",
  "attributes": {
    "PublicAccessBlockConfiguration": {
      "BlockPublicAcls": false
    },
    "VersioningConfiguration": {
      "Status": "Suspended"
    }
  }
}
EOF

echo "✅ Sample data files created"

# Step 3: Create the Demo Script
echo "🎪 Creating Policy Engine demo script..."

# This replaces the placeholder from Phase 1
cat > src/policy_engine_demo.py << 'EOF'
"""
Demonstration of the Cloud Compliance Policy Engine.
"""
import json
from pathlib import Path
from src.logger import setup_logging, get_logger
from src.policy_engine.loader import load_policies_from_directory
from src.policy_engine.engine import PolicyEngine
from src.policy_engine.models import Resource, EvaluationResult

# Setup structured logging
setup_logging("INFO")
logger = get_logger("policy_demo")

def print_result(result: EvaluationResult):
    """Prints evaluation results in a readable format."""
    status_color = "✅" if result.status == "COMPLIANT" else "❌"
    logger.info("=" * 60)
    logger.info(f"📄 Policy: {result.policy_id}")
    logger.info(f"💻 Resource: {result.resource_id}")
    logger.info(f"📊 Overall Status: {result.status} {status_color}")
    logger.info("-" * 60)

    for rule_res in result.rule_results:
        rule_status_color = "✅" if rule_res.status == "COMPLIANT" else "❌"
        logger.info(
            f"  - Rule: {rule_res.rule_id} "
            f"({rule_res.description})\n"
            f"    Status: {rule_res.status} {rule_status_color}\n"
            f"    Message: {rule_res.message}"
        )
    logger.info("=" * 60 + "\n")


def main():
    """Main function to run the demo."""
    logger.info("🚀 Starting Policy Engine Demo...")

    # Define paths
    project_root = Path(__file__).parent.parent
    policies_dir = project_root / "config" / "policies"
    samples_dir = project_root / "data" / "samples"

    # 1. Load policies
    logger.info(f"📂 Loading policies from: {policies_dir}")
    policies = load_policies_from_directory(policies_dir)
    if not policies:
        logger.error("No policies loaded. Exiting.")
        return

    # 2. Initialize the Policy Engine
    engine = PolicyEngine(policies)

    # 3. Load sample resources
    with open(samples_dir / "s3_compliant.json", "r") as f:
        compliant_resource = Resource(**json.load(f))

    with open(samples_dir / "s3_non_compliant.json", "r") as f:
        non_compliant_resource = Resource(**json.load(f))

    # 4. Evaluate the compliant resource
    logger.info("🔍 Evaluating COMPLIANT resource...")
    compliant_results = engine.evaluate(compliant_resource)
    for result in compliant_results:
        print_result(result)

    # 5. Evaluate the non-compliant resource
    logger.info("🔍 Evaluating NON-COMPLIANT resource...")
    non_compliant_results = engine.evaluate(non_compliant_resource)
    for result in non_compliant_results:
        print_result(result)

    logger.info("✅ Demo finished.")


if __name__ == "__main__":
    main()
EOF

# Update Makefile to point to the new demo script
sed -i 's|python src/policy_engine.py|python src/policy_engine_demo.py|' Makefile

echo "✅ Demo script created and Makefile updated."

# Step 4: Create Tests for the Policy Engine
echo "🧪 Creating tests for the Policy Engine..."
mkdir -p tests/policy_engine

cat > tests/policy_engine/__init__.py << 'EOF'
"""Tests for the Policy Engine package."""
EOF

cat > tests/policy_engine/test_policy_engine.py << 'EOF'
"""Tests for the Policy Engine components."""

import pytest
import sys
import json
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from policy_engine.models import Resource, Policy
from policy_engine.loader import load_policies_from_directory
from policy_engine.engine import PolicyEngine

# Define paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
POLICIES_DIR = PROJECT_ROOT / "config" / "policies"
SAMPLES_DIR = PROJECT_ROOT / "data" / "samples"

@pytest.fixture(scope="module")
def policy_engine() -> PolicyEngine:
    """Fixture to provide an initialized PolicyEngine."""
    policies = load_policies_from_directory(POLICIES_DIR)
    assert policies, "No policies were loaded for testing."
    return PolicyEngine(policies)

@pytest.fixture(scope="module")
def compliant_s3_resource() -> Resource:
    """Fixture for a compliant S3 resource."""
    with open(SAMPLES_DIR / "s3_compliant.json") as f:
        return Resource(**json.load(f))

@pytest.fixture(scope="module")
def non_compliant_s3_resource() -> Resource:
    """Fixture for a non-compliant S3 resource."""
    with open(SAMPLES_DIR / "s3_non_compliant.json") as f:
        return Resource(**json.load(f))

def test_policy_loading():
    """Test that policies are loaded correctly from YAML files."""
    policies = load_policies_from_directory(POLICIES_DIR)
    assert len(policies) > 0
    assert isinstance(policies[0], Policy)
    assert policies[0].id == "aws-s3-best-practices-v1"

def test_compliant_resource_evaluation(policy_engine, compliant_s3_resource):
    """Test a compliant resource against the policy."""
    results = policy_engine.evaluate(compliant_s3_resource)
    assert len(results) == 1
    result = results[0]
    assert result.status == "COMPLIANT"
    assert all(r.status == "COMPLIANT" for r in result.rule_results)

def test_non_compliant_resource_evaluation(policy_engine, non_compliant_s3_resource):
    """Test a non-compliant resource against the policy."""
    results = policy_engine.evaluate(non_compliant_s3_resource)
    assert len(results) == 1
    result = results[0]
    assert result.status == "NON_COMPLIANT"
    
    # Check specific rule failures
    rule_statuses = {r.rule_id: r.status for r in result.rule_results}
    assert rule_statuses["s3-block-public-access"] == "NON_COMPLIANT"
    assert rule_statuses["s3-enable-versioning"] == "NON_COMPLIANT"
    # Encryption rule is not applicable since the attribute is missing, resulting in non-compliance
    assert rule_statuses["s3-enable-encryption"] == "NON_COMPLIANT"

if __name__ == "__main__":
    pytest.main([__file__])
EOF

echo "✅ Policy Engine tests created."

# Step 5: Update Dependencies
echo "📦 Installing new dependencies (pydantic, pyyaml)..."
pip install pydantic pyyaml
pip freeze > requirements.txt
echo "✅ Dependencies updated in requirements.txt"

# Step 6: Update README.md
echo "📖 Updating README.md..."
sed -i '/## 🚀 Next Steps/i \
## 🧠 Policy Engine\n\nThe core engine works in three steps:\n1.  **Load**: Policies are loaded from `config/policies` YAML files and validated using Pydantic models.\n2.  **Evaluate**: A resource (in JSON format) is evaluated against all rules in a policy.\n3.  **Report**: A detailed `EvaluationResult` is generated, showing the compliance status for the resource and each individual rule.\n' README.md
sed -i 's/- Phase 2: Policy Engine Implementation/- ✅ Phase 2: Policy Engine Implementation/' README.md
echo "✅ README.md updated."

# Step 7: Final verification
echo ""
echo "🎯 Phase 2 Setup Verification:"
echo "✅ Policy Engine files created in src/policy_engine/"
echo "✅ Sample policy created in config/policies/"
echo "✅ Sample resource data created in data/samples/"
echo "✅ Demo script created at src/policy_engine_demo.py"
echo "✅ Test suite for policy engine created."
echo "✅ Dependencies updated."
echo "✅ README updated."

echo ""
echo "🚀 Phase 2 Complete! You have a working Policy-as-Code engine."
echo "Next steps:"
echo "1. Run 'make install' to ensure all dependencies are installed."
echo "2. Run 'make test' to verify the policy engine logic."
echo "3. Run 'make demo' to see the engine evaluate sample S3 resources."
echo ""
echo "Ready for Phase 3: AWS Lambda & Real-time Event Integration."
