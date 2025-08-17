"""
Maps failed rule IDs to remediation actions and triggers them.
"""

from typing import Optional

from aws_lambda_powertools import Logger

from . import actions

logger = Logger(child=True)

# This map is the core of the remediation engine.
# It connects a specific compliance rule to a corrective action.
REMEDIATION_MAP = {
    "s3-enable-versioning": actions.enable_s3_bucket_versioning,
    # "s3-block-public-access": actions.enforce_s3_public_access_block,
}


def trigger_remediation(
    resource_id: str, resource_region: Optional[str], rule_id: str
) -> bool:
    """
    Triggers the appropriate remediation action for a given failed rule.

    Args:
        resource_id: The ID of the non-compliant resource.
        resource_region: The AWS region of the resource.
        rule_id: The ID of the compliance rule that failed.

    Returns:
        True if remediation was successful, False otherwise.
    """
    remediation_action = REMEDIATION_MAP.get(rule_id)

    if not remediation_action:
        logger.warning(f"No remediation action defined for rule: {rule_id}")
        return False

    if not resource_region:
        logger.error(
            f"Cannot perform remediation for {resource_id} " "without a region."
        )
        return False

    try:
        logger.info(
            f"Triggering remediation '{remediation_action.__name__}' "
            f"for resource '{resource_id}' due to failed rule '{rule_id}'"
        )
        return remediation_action(resource_id, resource_region)
    except Exception as exc:
        logger.error(f"Remediation failed for {resource_id}: {exc}")
        return False
