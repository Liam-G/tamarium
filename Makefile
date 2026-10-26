.PHONY: test validate prove audit

test:
	python3 -m unittest discover -s tests -v

validate:
	python3 proofctl.py validate

prove:
	python3 proofctl.py prove --jobs 1 --timeout 60

audit:
	python3 proofctl.py audit --jobs 1 --timeout 60
