# Makefile to test kubectl_explain_failure scenarios

PYTHON = python
SCRIPT = explain_failure.py
FIXTURES_DIR = tests/fixtures
POD = $(FIXTURES_DIR)/pending_pod.json

# List of events fixtures
EVENTS = $(FIXTURES_DIR)/empty_events.json \
         $(FIXTURES_DIR)/events_configmap_missing.json \
         $(FIXTURES_DIR)/events_image_pull_error.json \
         $(FIXTURES_DIR)/events_image_pull_secret_missing.json \
         $(FIXTURES_DIR)/failed_scheduling_events_taint.json \
         $(FIXTURES_DIR)/failed_scheduling_events.json \
         $(FIXTURES_DIR)/node_disk_pressure.json \
		 $(FIXTURES_DIR)/events_pvc_not_bound.json

# Categories examples
ENABLE_CATS = Scheduling Volume Image
DISABLE_CATS = ConfigMap

# Default target
.PHONY: all
all: text json yaml verbose enabled disabled full

# 1. Default text output
.PHONY: text
text:
	@echo "=== TEXT OUTPUT ==="
	@for ev in $(EVENTS); do \
		$(PYTHON) $(SCRIPT) --pod $(POD) --events $$ev; \
	done

# 2. JSON output
.PHONY: json
json:
	@echo "=== JSON OUTPUT ==="
	@for ev in $(EVENTS); do \
		$(PYTHON) $(SCRIPT) --pod $(POD) --events $$ev --format json; \
	done

# 3. YAML output
.PHONY: yaml
yaml:
	@echo "=== YAML OUTPUT ==="
	@for ev in $(EVENTS); do \
		$(PYTHON) $(SCRIPT) --pod $(POD) --events $$ev --format yaml; \
	done

# 4. Verbose logging
.PHONY: verbose
verbose:
	@echo "=== VERBOSE MODE ==="
	@for ev in $(EVENTS); do \
		$(PYTHON) $(SCRIPT) --pod $(POD) --events $$ev --verbose; \
	done

# 5. Enable categories
.PHONY: enabled
enabled:
	@echo "=== ENABLE CATEGORIES ($(ENABLE_CATS)) ==="
	@for ev in $(EVENTS); do \
		$(PYTHON) $(SCRIPT) --pod $(POD) --events $$ev --enable-categories $(ENABLE_CATS) --verbose; \
	done

# 6. Disable categories
.PHONY: disabled
disabled:
	@echo "=== DISABLE CATEGORIES ($(DISABLE_CATS)) ==="
	@for ev in $(EVENTS); do \
		$(PYTHON) $(SCRIPT) --pod $(POD) --events $$ev --disable-categories $(DISABLE_CATS) --verbose; \
	done

# 7. Full test: verbose + enabled + disabled + JSON + YAML
.PHONY: full
full:
	@echo "=== FULL DIAGNOSTIC ==="
	@for ev in $(EVENTS); do \
		$(PYTHON) $(SCRIPT) --pod $(POD) --events $$ev \
			--enable-categories $(ENABLE_CATS) \
			--disable-categories $(DISABLE_CATS) \
			--verbose --format json; \
		$(PYTHON) $(SCRIPT) --pod $(POD) --events $$ev \
			--enable-categories $(ENABLE_CATS) \
			--disable-categories $(DISABLE_CATS) \
			--verbose --format yaml; \
	done
