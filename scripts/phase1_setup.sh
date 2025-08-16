#!/bin/bash

# ================================================================================
# Manual Phase 1 Setup - Cloud Compliance Framework
# Execute these commands step by step
# ================================================================================

# You're already in the right location, so let's continue from where you are
cd ~/projects/cloud-compliance-framework

echo "🚀 Setting up Cloud Compliance Framework - Phase 1"
echo "Current directory: $(pwd)"
echo "Python version: $(python --version)"

# Step 1: Create the complete directory structure
echo "📁 Creating project directory structure..."
mkdir -p src/{lambda_functions,policy_engine,compliance_rules,utils}
mkdir -p infrastructure/{terraform,cloudformation,ansible}
mkdir -p config/{environments,policies,templates}
mkdir -p tests/{unit,integration,e2e}
mkdir -p docs/{api,architecture,runbooks}
mkdir -p scripts/{deployment,monitoring}
mkdir -p data/{schemas,samples}
mkdir -p logs/reports
mkdir -p .github/workflows
mkdir -p monitoring/{grafana,prometheus}

echo "✅ Directory structure created"

# Step 2: Create essential configuration files
echo "⚙️ Creating configuration files..."

# Create pyproject.toml
cat > pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools>=65.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "cloud-compliance-framework"
version = "2.0.0"
description = "Modern Cloud Compliance & Policy-as-Code Framework"
authors = [{name = "Muhammad Arslan", email = "arslan@example.com"}]
requires-python = ">=3.8"
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
]

[tool.black]
line-length = 88
target-version = ['py38']
include = '\.pyi?$'

[tool.mypy]
python_version = "3.8"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
minversion = "6.0"
addopts = "-ra -q --cov=src --cov-report=html --cov-report=term"
testpaths = ["tests"]
EOF

# Create Makefile
cat > Makefile << 'EOF'
.PHONY: help install test lint format clean deploy demo

help:
	@echo "Available commands:"
	@echo "  install     Install dependencies"
	@echo "  test        Run tests"
	@echo "  lint        Run linting"
	@echo "  format      Format code"
	@echo "  clean       Clean build artifacts"
	@echo "  deploy      Deploy to AWS"
	@echo "  demo        Run policy engine demo"

install:
	pip install -r requirements.txt
	@echo "✅ Dependencies installed"

test:
	@echo "🧪 Running tests..."
	python -m pytest tests/ -v --tb=short
	@echo "✅ Tests completed"

lint:
	@echo "🔍 Running linting..."
	python -m flake8 src --max-line-length=88 --ignore=E203,W503 || echo "Install flake8: pip install flake8"
	@echo "✅ Linting completed"

format:
	@echo "🎨 Formatting code..."
	python -m black src tests || echo "Install black: pip install black"
	@echo "✅ Code formatted"

clean:
	@echo "🧹 Cleaning build artifacts..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf build/ dist/ *.egg-info/ .coverage htmlcov/
	@echo "✅ Cleanup completed"

demo:
	@echo "🎪 Running policy engine demo..."
	python src/policy_engine.py
	@echo "✅ Demo completed"

deploy:
	@echo "🚀 Deploying to AWS..."
	./scripts/deployment/deploy.sh
EOF

# Create environment configuration
cat > config/environments/local.yaml << 'EOF'
environment: local
aws:
  region: eu-west-2
  profile: default
  account_id: "275057777261"
  
resources:
  lambda:
    runtime: python3.11
    timeout: 300
    memory_size: 512
    environment_variables:
      LOG_LEVEL: INFO
      ENVIRONMENT: local
      
  dynamodb:
    billing_mode: PAY_PER_REQUEST
    point_in_time_recovery: true
    
  s3:
    versioning: true
    encryption: true
    public_access_block: true
    
logging:
  level: INFO
  format: json
  
monitoring:
  enable_metrics: true
  enable_tracing: true
  retention_days: 30
EOF

echo "✅ Configuration files created"

# Step 3: Create core source files
echo "📝 Creating core source files..."

# Create src/__init__.py
cat > src/__init__.py << 'EOF'
"""
Cloud Compliance Framework
Modern Policy-as-Code enforcement system
"""

__version__ = "2.0.0"
__author__ = "Muhammad Arslan"
EOF

# Create src/config.py
cat > src/config.py << 'EOF'
"""Configuration management module."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Environment
    environment: str = Field(default="local", env="ENVIRONMENT")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # AWS Configuration
    aws_region: str = Field(default="eu-west-2", env="AWS_REGION")
    aws_account_id: str = Field(default="275057777261", env="AWS_ACCOUNT_ID")
    aws_profile: str = Field(default="default", env="AWS_PROFILE")
    
    # Lambda Configuration
    lambda_timeout: int = Field(default=300, env="LAMBDA_TIMEOUT")
    lambda_memory_size: int = Field(default=512, env="LAMBDA_MEMORY_SIZE")
    
    # Monitoring
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    enable_tracing: bool = Field(default=True, env="ENABLE_TRACING")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config" / "environments" / "local.yaml"
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


# Global settings instance
settings = Settings()
EOF

# Create src/logger.py
cat > src/logger.py << 'EOF'
"""Structured logging configuration."""

import sys
from pathlib import Path
from loguru import logger


def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured logging."""
    
    # Remove default handler
    logger.remove()
    
    # Add console handler
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
               "<level>{message}</level>",
        level=log_level,
        colorize=True,
        serialize=False,
    )
    
    # Ensure logs directory exists
    Path("logs").mkdir(exist_ok=True)
    
    # Add file handler
    logger.add(
        "logs/compliance-framework.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=log_level,
        rotation="10 MB",
        retention="30 days",
        compression="gz",
    )


def get_logger(name: str):
    """Get a configured logger instance."""
    return logger.bind(name=name)
EOF

echo "✅ Core source files created"

# Step 4: Create basic test files
echo "🧪 Creating test files..."

# Create a simple test
cat > tests/__init__.py << 'EOF'
"""Test package for cloud compliance framework."""
EOF

cat > tests/test_basic.py << 'EOF'
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
EOF

echo "✅ Test files created"

# Step 5: Create .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
.venv/
venv/
ENV/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Logs
logs/
*.log

# AWS
.aws/
*.pem

# Environment variables
.env
.env.local

# Test coverage
htmlcov/
.coverage
.pytest_cache/

# Terraform
*.tfstate
*.tfstate.*
.terraform/

# OS
.DS_Store
Thumbs.db
EOF

echo "✅ Git configuration created"

# Step 6: Install additional dependencies and update requirements
echo "📦 Installing additional dependencies..."

# Install development and testing tools
pip install pytest pytest-cov black flake8 mypy bandit pre-commit safety

# Update requirements.txt
pip freeze > requirements.txt

echo "✅ Dependencies updated"

# Step 7: Create a basic README
cat > README.md << 'EOF'
# Cloud Compliance & Policy-as-Code Framework

A modern, scalable framework for automated cloud compliance enforcement using Policy-as-Code principles.

## 🚀 Features

- **Policy-as-Code**: Define compliance rules in declarative YAML
- **Multi-Cloud Support**: AWS, Azure, GCP (extensible)
- **Real-time Remediation**: Automated compliance enforcement
- **Comprehensive Monitoring**: Metrics, alerting, and dashboards
- **CI/CD Integration**: Automated testing and deployment
- **Security-First**: Built-in security scanning and best practices

## 📊 Quick Start

```bash
# Activate environment
source .venv/bin/activate

# Install dependencies
make install

# Run tests
make test

# Run policy demo
make demo
```

## 📁 Project Structure

```
├── src/                    # Source code
│   ├── lambda_functions/   # AWS Lambda functions
│   ├── policy_engine/      # Policy evaluation engine
│   └── compliance_rules/   # Compliance rule definitions
├── infrastructure/         # Infrastructure as Code
├── config/                # Configuration files
├── tests/                 # Test suites
└── docs/                  # Documentation
```

## 🧪 Development

```bash
# Format code
make format

# Run linting
make lint

# Clean build artifacts
make clean
```

## 📋 Phase 1 Status

- ✅ Project structure created
- ✅ Core configuration files
- ✅ Basic source code templates
- ✅ Testing framework setup
- ✅ Development tools configured

## 🚀 Next Steps

- Phase 2: Policy Engine Implementation
- Phase 3: AWS Lambda Integration
- Phase 4: Real-time Event Processing
- Phase 5: Monitoring & Alerting

---

**Version**: 2.0.0  
**Author**: Muhammad Arslan  
**Last Updated**: January 2025
EOF

# Step 8: Initialize git if not already done
if [ ! -d ".git" ]; then
    echo "🔧 Initializing Git repository..."
    git init
    git config user.name "Muhammad Arslan"
    git config user.email "arslan@example.com"
    git add .
    git commit -m "Initial commit: Phase 1 setup complete"
    echo "✅ Git repository initialized"
fi

# Step 9: Show project structure
echo "📁 Project structure created:"
if command -v tree >/dev/null 2>&1; then
    tree -L 3 -a
else
    find . -type d | head -20 | sort
fi

# Step 10: Final verification
echo ""
echo "🎯 Phase 1 Setup Verification:"
echo "✅ Directory structure: $(find . -type d | wc -l) directories created"
echo "✅ Configuration files: $(find config -name "*.yaml" | wc -l) config files"
echo "✅ Source files: $(find src -name "*.py" | wc -l) Python files"
echo "✅ Test files: $(find tests -name "*.py" | wc -l) test files"
echo "✅ Dependencies: $(pip list | wc -l) packages installed"

echo ""
echo "🚀 Phase 1 Complete! Next steps:"
echo "1. Run: make test"
echo "2. Run: make demo (after policy engine is created)"
echo "3. Ready for Phase 2: Policy Engine Implementation"

echo ""
echo "📍 Current location: $(pwd)"
echo "🐍 Python version: $(python --version)"
echo "📦 Virtual environment: $(which python)"
