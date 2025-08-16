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
	python src/policy_engine_demo.py
	@echo "✅ Demo completed"

deploy:
	@echo "🚀 Deploying to AWS..."
	./scripts/deployment/deploy.sh

report:
	@echo "📊 Generating compliance report..."
	python scripts/monitoring/generate_report.py


security-scan:
	@echo "🛡️  Running security scans..."
	@echo "--- Running Bandit (SAST) ---"
	bandit -r src/ -s B101
	@echo "--- Running Safety (Dependency Check) ---"
	safety check --full-report

