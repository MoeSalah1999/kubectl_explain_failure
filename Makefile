# Makefile to test kubectl_explain_failure scenarios

PYTHON = python
SCRIPT = run_explain.py
FIXTURES_DIR = tests/fixtures

PODS := $(wildcard $(FIXTURES_DIR)/*pod*.json)
EVENTS := $(wildcard $(FIXTURES_DIR)/*events*.json)

ENABLE_CATS = Scheduling Volume Image
DISABLE_CATS = ConfigMap

.PHONY: all
all: text json yaml verbose enabled disabled full

# ----------------------------
# 1. Default text output
# ----------------------------
.PHONY: text
text:
	@echo "=== TEXT OUTPUT ==="
	@for pod in $(PODS); do \
		for ev in $(EVENTS); do \
			$(PYTHON) $(SCRIPT) --pod $$pod --events $$ev; \
		done \
	done

# ----------------------------
# 2. JSON output
# ----------------------------
.PHONY: json
json:
	@echo "=== JSON OUTPUT ==="
	@for pod in $(PODS); do \
		for ev in $(EVENTS); do \
			$(PYTHON) $(SCRIPT) --pod $$pod --events $$ev --format json; \
		done \
	done

# ----------------------------
# 3. YAML output
# ----------------------------
.PHONY: yaml
yaml:
	@echo "=== YAML OUTPUT ==="
	@for pod in $(PODS); do \
		for ev in $(EVENTS); do \
			$(PYTHON) $(SCRIPT) --pod $$pod --events $$ev --format yaml; \
		done \
	done

# ----------------------------
# 4. Verbose logging
# ----------------------------
.PHONY: verbose
verbose:
	@echo "=== VERBOSE MODE ==="
	@for pod in $(PODS); do \
		for ev in $(EVENTS); do \
			$(PYTHON) $(SCRIPT) --pod $$pod --events $$ev --verbose; \
		done \
	done

# ----------------------------
# 5. Enable categories
# ----------------------------
.PHONY: enabled
enabled:
	@echo "=== ENABLE CATEGORIES ($(ENABLE_CATS)) ==="
	@for pod in $(PODS); do \
		for ev in $(EVENTS); do \
			$(PYTHON) $(SCRIPT) --pod $$pod --events $$ev --enable-categories "$(ENABLE_CATS)" --verbose; \
		done \
	done

# ----------------------------
# 6. Disable categories
# ----------------------------
.PHONY: disabled
disabled:
	@echo "=== DISABLE CATEGORIES ($(DISABLE_CATS)) ==="
	@for pod in $(PODS); do \
		for ev in $(EVENTS); do \
			$(PYTHON) $(SCRIPT) --pod $$pod --events $$ev --disable-categories "$(DISABLE_CATS)" --verbose; \
		done \
	done

# ----------------------------
# 7. Full test
# ----------------------------
.PHONY: full
full:
	@echo "=== FULL DIAGNOSTIC ==="
	@for pod in $(PODS); do \
		for ev in $(EVENTS); do \
			$(PYTHON) $(SCRIPT) --pod $$pod --events $$ev --enable-categories "$(ENABLE_CATS)" --disable-categories "$(DISABLE_CATS)" --verbose --format json; \
			$(PYTHON) $(SCRIPT) --pod $$pod --events $$ev --enable-categories "$(ENABLE_CATS)" --disable-categories "$(DISABLE_CATS)" --verbose --format yaml; \
		done \
	done
