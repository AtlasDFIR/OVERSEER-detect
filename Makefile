.PHONY: validate test coverage check integration integration-up integration-down clean

# Fast, dependency-light checks (the default CI gate).
validate:
	python3 scripts/validate_detections.py

test:
	python3 scripts/test_detections.py

coverage:
	python3 scripts/coverage_report.py

check: validate test coverage
	@echo "All fast checks passed."

# Heavy end-to-end path against real Splunk.
SPLUNK_PASSWORD ?= Changed123!
SPLUNK_HEC_TOKEN ?= 00000000-0000-0000-0000-000000000000
export SPLUNK_PASSWORD
export SPLUNK_HEC_TOKEN

integration-up:
	cd integration && docker compose up -d && ./wait_for_splunk.sh
	python3 integration/generate_data.py

integration: integration-up
	pip install -r integration/requirements.txt
	python3 integration/run_integration_tests.py

integration-down:
	cd integration && docker compose down -v

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -f integration/_indexed_events.json
