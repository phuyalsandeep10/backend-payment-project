# Quality Assurance Makefile
# Provides easy access to all quality tools and checks

# Configuration
PYTHON = python3
PROJECT_ROOT = ../..
QUALITY_DIR = .
REPORTS_DIR = reports

# Default target
.PHONY: help
help:
	@echo "🎯 PRS Code Quality Tools"
	@echo "=========================="
	@echo ""
	@echo "Quality Checks:"
	@echo "  check                    Run all quality checks"
	@echo "  check-complexity         Analyze code complexity"
	@echo "  check-gates             Enforce quality gates"
	@echo "  check-fast              Quick quality check (no analysis)"
	@echo ""
	@echo "Reports & Dashboards:"
	@echo "  dashboard               Generate HTML quality dashboard"
	@echo "  report                  Generate comprehensive quality report"
	@echo "  track-history           Save current metrics to history database"
	@echo ""
	@echo "CI/CD Integration:"
	@echo "  ci-check                CI/CD quality check (fails build on violation)"
	@echo "  pre-commit-hook         Generate pre-commit hook"
	@echo "  github-action           Generate GitHub Actions workflow"
	@echo ""
	@echo "Setup & Maintenance:"
	@echo "  setup                   Setup quality tools and dependencies"
	@echo "  clean                   Clean generated reports and cache"
	@echo "  init-db                 Initialize quality metrics database"

# === QUALITY CHECKS ===

.PHONY: check
check: check-complexity check-gates
	@echo "✅ All quality checks completed"

.PHONY: check-complexity
check-complexity:
	@echo "🔍 Running code complexity analysis..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/code_complexity_analyzer.py \
		--project-root . \
		--output $(QUALITY_DIR)/$(REPORTS_DIR)/complexity-report.json \
		--verbose

.PHONY: check-gates
check-gates:
	@echo "🎯 Checking quality gates..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py \
		--check \
		--verbose \
		--output $(QUALITY_DIR)/$(REPORTS_DIR)/quality-gates.json

.PHONY: check-fast
check-fast:
	@echo "⚡ Running fast quality check..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py \
		--check \
		--module core_config \
		--module apps/authentication

# === REPORTS & DASHBOARDS ===

.PHONY: dashboard
dashboard: $(REPORTS_DIR)
	@echo "📊 Generating quality dashboard..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_dashboard.py \
		--generate-dashboard \
		--output scripts/quality/$(REPORTS_DIR)/dashboard.html
	@echo "🌐 Dashboard available at: file://$(PWD)/$(REPORTS_DIR)/dashboard.html"

.PHONY: report
report: $(REPORTS_DIR)
	@echo "📋 Generating comprehensive quality report..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/code_complexity_analyzer.py \
		--project-root . \
		--output $(QUALITY_DIR)/$(REPORTS_DIR)/quality-report.json \
		--verbose
	@echo "💾 Report saved to: $(REPORTS_DIR)/quality-report.json"

.PHONY: track-history
track-history:
	@echo "📈 Tracking quality metrics to history..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_dashboard.py \
		--track-history
	@echo "✅ Quality metrics saved to history database"

# === CI/CD INTEGRATION ===

.PHONY: ci-check
ci-check:
	@echo "🚀 Running CI/CD quality check..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py \
		--check \
		--ci-mode \
		--fail-build \
		--output $(QUALITY_DIR)/$(REPORTS_DIR)/ci-results.json

.PHONY: pre-commit-hook
pre-commit-hook:
	@echo "🪝 Generating pre-commit hook..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py \
		--generate-pre-commit-hook .git/hooks/pre-commit
	@echo "✅ Pre-commit hook installed at .git/hooks/pre-commit"

.PHONY: github-action
github-action:
	@echo "🐙 Generating GitHub Actions workflow..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py \
		--generate-github-action .github/workflows/quality-gates.yml
	@echo "✅ GitHub Action generated at .github/workflows/quality-gates.yml"

# === SETUP & MAINTENANCE ===

.PHONY: setup
setup: $(REPORTS_DIR) init-db
	@echo "🔧 Setting up quality tools..."
	@pip install -r requirements.txt 2>/dev/null || echo "⚠️  Install requirements manually if needed"
	@echo "✅ Quality tools setup completed"

.PHONY: clean
clean:
	@echo "🧹 Cleaning generated files..."
	@rm -rf $(REPORTS_DIR)/*.json
	@rm -rf $(REPORTS_DIR)/*.html
	@rm -rf __pycache__/
	@rm -rf *.pyc
	@echo "✅ Clean completed"

.PHONY: init-db
init-db:
	@echo "🗄️  Initializing quality metrics database..."
	@cd $(PROJECT_ROOT) && $(PYTHON) -c "from scripts.quality.quality_dashboard import QualityDatabase; QualityDatabase().init_database()"
	@echo "✅ Database initialized"

# === UTILITY TARGETS ===

.PHONY: status
status:
	@echo "📊 Quality Status Summary"
	@echo "========================"
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py --check --verbose | head -20
	@echo ""
	@echo "📁 Generated Reports:"
	@ls -la $(REPORTS_DIR)/ 2>/dev/null || echo "No reports generated yet"

.PHONY: watch
watch:
	@echo "👀 Watching for changes and running quality checks..."
	@echo "💡 Install 'entr' for file watching: brew install entr (macOS) or apt install entr (Ubuntu)"
	@find $(PROJECT_ROOT) -name "*.py" | entr -c make check-fast

# Create directories
$(REPORTS_DIR):
	@mkdir -p $(REPORTS_DIR)

# === MODULE-SPECIFIC CHECKS ===

.PHONY: check-core-config
check-core-config:
	@echo "🔍 Checking core_config module..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py \
		--check --module core_config --verbose

.PHONY: check-authentication
check-authentication:
	@echo "🔍 Checking authentication module..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py \
		--check --module apps/authentication --verbose

.PHONY: check-deals
check-deals:
	@echo "🔍 Checking deals module..."
	@cd $(PROJECT_ROOT) && $(PYTHON) scripts/quality/quality_gates.py \
		--check --module apps/deals --verbose

# === INTEGRATION EXAMPLES ===

.PHONY: example-pre-commit
example-pre-commit:
	@echo "📝 Example pre-commit integration:"
	@echo ""
	@echo "Add to .pre-commit-config.yaml:"
	@echo "repos:"
	@echo "  - repo: local"
	@echo "    hooks:"
	@echo "      - id: quality-gates"
	@echo "        name: Quality Gates"
	@echo "        entry: make -C scripts/quality ci-check"
	@echo "        language: system"
	@echo "        pass_filenames: false"

.PHONY: example-ci
example-ci:
	@echo "🚀 Example CI/CD integration:"
	@echo ""
	@echo "GitHub Actions (.github/workflows/quality.yml):"
	@echo "jobs:"
	@echo "  quality:"
	@echo "    runs-on: ubuntu-latest"
	@echo "    steps:"
	@echo "      - uses: actions/checkout@v3"
	@echo "      - name: Run Quality Gates"
	@echo "        run: |"
	@echo "          cd Backend_PRS"
	@echo "          make -C scripts/quality ci-check"
