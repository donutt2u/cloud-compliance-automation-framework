"""
Automated Remediation Engine.

This engine maps non-compliant rule IDs to specific, automated
remediation actions.
"""

from .handler import trigger_remediation

__all__ = ["trigger_remediation"]
