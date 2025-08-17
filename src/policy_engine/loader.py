"""Loads and validates policy files."""

from pathlib import Path
from typing import List

import yaml

from src.logger import get_logger

from .models import Policy

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
