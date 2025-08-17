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
    # Allow flexible version (v1, v2, etc.)
    assert policies[0].id.startswith("aws-s3-best-practices")

def test_compliant_resource_evaluation(policy_engine, compliant_s3_resource):
    """Test a compliant resource against the policy."""
    results = policy_engine.evaluate(compliant_s3_resource)
    assert len(results) == 1
    result = results[0]

    # Debug which rules failed (if any)
    for r in result.rule_results:
        print(f"Rule {r.rule_id}: {r.status}")

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
    assert rule_statuses["s3-enable-encryption"] == "NON_COMPLIANT"
    assert rule_statuses["s3-logging-enabled"] == "NON_COMPLIANT"

if __name__ == "__main__":
    pytest.main([__file__])

