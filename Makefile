# claude-code-security — a Claude Code security plugin.
#   make help     # list targets

.PHONY: help test demo validate install down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-9s\033[0m %s\n", $$1, $$2}'

test: ## Run the hook test suite (uv)
	uv run pytest -q

demo: ## Show each hook blocking a malicious vs allowing a benign event (no Claude, free)
	@python3 scripts/demo.py

validate: ## Validate plugin + marketplace JSON (uses `claude` if present)
	@command -v claude >/dev/null 2>&1 && claude plugin validate . || \
		python3 -c "import json; json.load(open('.claude-plugin/plugin.json')); json.load(open('.claude-plugin/marketplace.json')); json.load(open('hooks/hooks.json')); print('JSON OK (install claude for full validation)')"

install: ## Print how to install this plugin into Claude Code
	@echo "claude plugin marketplace add teodorio95-portofolio/claude-code-security"
	@echo "then in Claude Code:  /plugin install claude-code-security@teodorio-security"
	@echo "or test locally:      claude --plugin-dir ."

down: ## Remove caches
	rm -rf .venv .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
