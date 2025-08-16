"""Basic tests for the compliance framework."""

import pytest
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def test_imports():
    """Test that basic imports work."""
    try:
        import config
        import logger
        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")

def test_config_loading():
    """Test configuration loading."""
    from config import settings
    assert settings.environment == "local"
    assert settings.aws_region == "eu-west-2"

def test_logger_setup():
    """Test logger setup."""
    from logger import setup_logging, get_logger
    setup_logging("INFO")
    log = get_logger("test")
    assert log is not None

if __name__ == "__main__":
    pytest.main([__file__])
