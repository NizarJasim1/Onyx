.PHONY: seal verify check run baseline score all
PY ?= python3
BASE ?= http://localhost:8888

seal:        ## pre-register: hash-seal the oracle + protocol (BEFORE the run)
	$(PY) seal.py
verify:      ## verify the seal still matches
	$(PY) seal.py verify
check:       ## offline: list the probes built from the sealed oracle
	$(PY) runner.py --check
run:         ## OPERATOR: live run against crAPI -> findings.json + run_manifest.json
	$(PY) runner.py --run --base-url $(BASE) --out .
baseline:    ## print real Autorize/ZAP config for the head-to-head
	$(PY) baseline_runner.py --tool
score:       ## score findings.json against the sealed oracle (awards the tier)
	$(PY) scorer.py findings.json run_manifest.json

selftest:    ## offline: build a PCM bundle from spec-replay and self-verify (no net)
	$(PY) prove.py --offline-selftest
prove:       ## OPERATOR: live run -> self-verifying PCM bundle (needs net)
	$(PY) prove.py --run --base-url $(BASE) --out bundle.json
verify:      ## ANYONE: verify a PCM bundle, trusting no one
	$(PY) verify.py bundle.json
conformance: ## offline: ONYX vs crAPI's spec-documented behavior + negative control
	$(PY) -c "import sys; sys.path.insert(0,'.'); from conformance import run_conformance, _gt; import json; print(json.dumps(run_conformance(), indent=2)[:1200])"

all: seal run score
