.PHONY: validate test manifest all

validate:
	python3 scripts/validate_package.py

test:
	python3 -m unittest discover -s tests -v

manifest:
	python3 scripts/build_manifest.py

all: validate test manifest
