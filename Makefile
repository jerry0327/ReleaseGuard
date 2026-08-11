PYTHON ?= python3

.PHONY: test check build clean

test:
	$(PYTHON) -m unittest discover -s tests -v

check:
	$(PYTHON) scripts/release_check.py
	$(PYTHON) -m compileall -q releaseguard tests scripts

build: check test
	rm -rf dist build *.egg-info
	$(PYTHON) -m pip wheel . --no-deps --wheel-dir dist

clean:
	rm -rf dist build *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
