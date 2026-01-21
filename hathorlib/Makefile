py_sources = hathorlib/ $(wildcard *.py)
py_tests = tests/ $(wildcard *.py)

.PHONY: all
all: check tests

# testing:

tests_lib = ./tests/

pytest_flags = -p no:warnings --cov-report=term --cov-report=html --cov=hathorlib
mypy_tests_flags = --warn-unused-configs --disallow-incomplete-defs --no-implicit-optional --warn-redundant-casts --strict-equality --disallow-subclassing-any --warn-return-any --disallow-untyped-decorators --show-error-codes
mypy_sources_flags = --strict --show-error-codes

.PHONY: tests
tests:
	pytest --durations=10 $(pytest_flags) --doctest-modules hathorlib --cov-fail-under=60 $(tests_lib)

# checking:
#
.PHONY: mypy
mypy: mypy-sources mypy-tests

.PHONY: mypy-sources
mypy-sources: $(py_sources)
	mypy $(mypy_sources_flags) $^

.PHONY: mypy-tests
mypy-tests: $(py_tests)
	mypy $(mypy_tests_flags) $^

.PHONY: flake8
flake8: $(py_sources) $(py_tests)
	flake8 $^

.PHONY: isort-check
isort-check: $(py_sources) $(py_tests)
	isort --check-only $^

.PHONY: check
check: flake8 isort-check mypy

# formatting:

.PHONY: fmt
fmt: isort

.PHONY: isort
isort: $(py_sources) $(py_tests)
	isort -ac $^

# cleaning:

.PHONY: clean-pyc
clean-pyc:
	find hathorlib tests -name \*.pyc -delete
	find hathorlib tests -name __pycache__ -delete
