"""Main Policy Engine orchestrator."""

from typing import List

from src.logger import get_logger

from .evaluator import evaluate_rule
from .models import EvaluationResult, Policy, Resource, RuleResult, Status

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
                status: Status = Status.COMPLIANT if compliant else Status.NON_COMPLIANT
                if compliant:
                    message = f"Attribute '{rule.attribute}' is compliant."
                else:
                    message = (
                        f"Violation: Attribute '{rule.attribute}' is non-compliant. "
                        f"Expected condition: {rule.condition} {rule.value}."
                    )

                if not compliant:
                    is_compliant = False

                rule_results.append(
                    RuleResult(
                        rule_id=rule.id,
                        description=rule.description,
                        status=status,
                        message=message,
                    )
                )
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.id}: {e}")
                is_compliant = False
                rule_results.append(
                    RuleResult(
                        rule_id=rule.id,
                        description=rule.description,
                        status=Status.ERROR,
                        message=str(e),
                    )
                )

        overall_status: Status = (
            Status.COMPLIANT if is_compliant else Status.NON_COMPLIANT
        )
        return EvaluationResult(
            policy_id=policy.id,
            resource_id=resource.id,
            status=overall_status,
            rule_results=rule_results,
        )
