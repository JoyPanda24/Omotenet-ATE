# Makefile for Attack Thinking Engine

.PHONY: help setup install test run demo clean lint format docs

help:
	@echo "Attack Thinking Engine - Make Commands"
	@echo ""
	@echo "Setup and Installation:"
	@echo "  make setup        - Complete setup (venv + dependencies)"
	@echo "  make install      - Install dependencies in venv"
	@echo ""
	@echo "Development:"
	@echo "  make test         - Run all tests"
	@echo "  make lint         - Run code linting"
	@echo "  make format       - Format code with black/isort"
	@echo ""
	@echo "Running:"
	@echo "  make demo         - Run basic demo"
	@echo "  make demo-complex - Run complex demo"
	@echo "  make demo-idor    - Run IDOR demo"
	@echo ""
	@echo "Utilities:"
	@echo "  make docs         - Generate documentation"
	@echo "  make clean        - Remove generated files"
	@echo "  make shell        - Start Python shell with ATE"

# Setup virtual environment
setup:
	bash setup.sh

# Install dependencies
install:
	pip install --upgrade pip
	pip install -r requirements.txt

# Run all tests
test:
	pytest tests/ -v --cov=ate --cov-report=html

# Run specific test
test-%:
	pytest tests/test_$*.py -v

# Lint code
lint:
	pylint ate/ --exit-zero
	flake8 ate/ --max-line-length=100

# Format code
format:
	black ate/ tests/ examples/
	isort ate/ tests/ examples/

# Generate documentation
docs:
	@echo "Documentation files:"
	@echo "  - README.md"
	@echo "  - QUICKSTART.md"
	@echo "  - DEVELOPER.md"

# Run basic demo
demo:
	python -m ate.cli.main demo --example basic

# Run complex demo
demo-complex:
	python -m ate.cli.main demo --example complex

# Run IDOR demo
demo-idor:
	python -m ate.cli.main demo --example idor

# Run sample analysis
analyze:
	python -m ate.cli.main analyze \
		--graph-file examples/sample_graph.json \
		--findings-file examples/sample_findings.json \
		--output examples/analysis_results.json

# Scan sample URLs for IDOR
scan:
	python -m ate.cli.main scan-idor \
		--urls-file examples/sample_urls.txt \
		--output examples/idor_findings.json

# Run comprehensive example
example:
	python examples/comprehensive_example.py

# Interactive shell
shell:
	python -c "from ate import *; import readline; import code; code.InteractiveConsole(globals()).interact()"

# Clean generated files
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf .pytest_cache .coverage htmlcov/
	rm -f examples/*.json

# Show project structure
tree:
	@echo "Project Structure:"
	@find . -type f -name '*.py' | head -30 | sed 's|./||' | sort

# Help for venv
venv-help:
	@echo "Virtual Environment Commands:"
	@echo "  Activate:   source venv/bin/activate"
	@echo "  Deactivate: deactivate"

.DEFAULT_GOAL := help
