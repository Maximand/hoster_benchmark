.PHONY: install lint test run clean

install:
\tpython -m pip install -U pip
\tpip install -e .[dev]

lint:
\tpre-commit run --all-files

test:
\tpytest

run:
\thb run --config config/pipeline.yaml

clean:
\trm -rf data/work/* data/output/* || true
