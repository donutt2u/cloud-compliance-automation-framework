"""Core rule evaluation logic."""

from typing import Any

from .models import Dict, Rule


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
    attrs = attr_string.split(".")
    for attr in attrs:
        if isinstance(obj, dict):
            obj = obj.get(attr)
        else:
            return None  # Path is invalid
        if obj is None:
            return None  # Attribute not found
    return obj
