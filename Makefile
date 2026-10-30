.PHONY: test demo mutation gate lint ci clean
PY ?= python3

test:            ## run the full stdlib test suite (the canonical gate)
	$(PY) tests/run_all.py

demo:            ## run the labeled calibration (byte-identical guarantee)
	$(PY) -m authpath demo

mutation:        ## run the mutation harnesses (fail below their floors)
	$(PY) tools/mutate_conservation.py
	$(PY) tools/mutate_evidence.py
	$(PY) tools/mutate_certificate.py

gate:            ## RL20 no-bare-metrics gate over judge-facing claims
	$(PY) tools/check_claims.py

lint:            ## ruff (correctness rules)
	ruff check authpath tests tools

ci: test demo mutation gate lint   ## everything CI runs, locally
	@echo "ALL GREEN"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
