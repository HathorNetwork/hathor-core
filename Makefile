
.PHONY: all
all: tests pep8

.PHONY: tests
tests:
	nosetests --with-coverage --cover-package=hathor --cover-html

.PHONY: pep8
pep8:
	flake8 hathor/ tests/ *.py



