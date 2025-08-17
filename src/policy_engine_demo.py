"""
Demonstration of the Cloud Compliance Policy Engine.
"""

import json
from pathlib import Path

from src.logger import get_logger, setup_logging
from src.policy_engine.engine import PolicyEngine
from src.policy_engine.loader import load_policies_from_directory
from src.policy_engine.models import EvaluationResult, Resource

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
