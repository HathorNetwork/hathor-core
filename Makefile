
.PHONY: all
all: tests pep8

.PHONY: tests
tests:
	pytest --cov=hathor --cov-fail-under=70 ./tests

.PHONY: pep8
pep8:
	flake8 hathor/ tests/ tools/ *.py



