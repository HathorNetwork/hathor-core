py_sources = hathor/ hathor_tests/ extras/custom_tests/

.PHONY: all
all: check tests

# testing:

tests_cli = hathor_tests/cli/
tests_nano = hathor_tests/nanocontracts/ hathor_tests/tx/test_indexes_nc_history.py hathor_tests/resources/nanocontracts/
tests_lib = $(filter-out ${tests_cli} hathor_tests/__pycache__/, $(dir $(wildcard hathor_tests/*/.)))
tests_ci = extras/github/

pytest_flags = -p no:warnings --cov-report=term --cov-report=html --cov-report=xml --cov=hathor

#--strict-equality
#--check-untyped-defs

#--disallow-untyped-defs
#--disallow-any-generics
#--disallow-subclassing-any
#--warn-return-any
#--disallow-untyped-calls
#--disallow-untyped-decorators

#--implicit-reexport
#--no-implicit-reexport

.PHONY: tests-nano
tests-nano:
	pytest --durations=10 --cov-report=html --cov=hathor/nanocontracts/ --cov-config=.coveragerc_full -p no:warnings $(tests_nano)

.PHONY: tests-cli
tests-cli:
	pytest --durations=10 --cov=hathor_cli/ --cov-config=.coveragerc_full --cov-fail-under=27 -p no:warnings $(tests_cli)

.PHONY: tests-doctests
tests-doctests:
	pytest --durations=10 $(pytest_flags) --doctest-modules hathor

.PHONY: tests-lib
tests-lib:
	pytest --durations=10 $(pytest_flags) --doctest-modules hathor $(tests_lib)

.PHONY: tests-quick
tests-quick:
	pytest --durations=10 $(pytest_flags) --doctest-modules hathor $(tests_lib) --maxfail=1 -m "not slow"

.PHONY: tests-genesis
tests-genesis:
	HATHOR_TEST_CONFIG_YAML='./hathorlib/hathorlib/conf/mainnet.yml' pytest -n0 hathor_tests/tx/test_genesis.py
	HATHOR_TEST_CONFIG_YAML='./hathorlib/hathorlib/conf/testnet.yml' pytest -n0 hathor_tests/tx/test_genesis.py
	HATHOR_TEST_CONFIG_YAML='./hathorlib/hathorlib/conf/nano_testnet.yml' pytest -n0 hathor_tests/tx/test_genesis.py

.PHONY: tests-ci
tests-ci:
	pytest $(tests_ci)

.PHONY: tests-custom
tests-custom:
	bash ./extras/custom_tests.sh

.PHONY: tests
tests: tests-cli tests-lib tests-genesis tests-custom tests-ci

.PHONY: tests-full
tests-full:
	pytest $(pytest_flags) --durations=10 --cov-config=.coveragerc_full ./hathor_tests

# checking:

.PHONY: mypy
mypy:
	mypy -p hathor -p hathor_tests -p extras.custom_tests

.PHONY: dmypy
dmypy:
	dmypy run --timeout 86400 -- -p hathor -p hathor_tests -p extras.custom_tests

.PHONY: flake8
flake8:
	flake8 $(py_sources)

.PHONY: isort-check
isort-check:
	isort --ac --check-only $(py_sources)

.PHONY: yamllint
yamllint:
	yamllint .

.PHONY: check-custom
check-custom:
	bash ./extras/custom_checks.sh

.PHONY: check
check: check-custom yamllint flake8 isort-check mypy

.PHONY: dcheck
dcheck: check-custom yamllint flake8 isort-check dmypy

# formatting:

.PHONY: fmt
fmt: isort

.PHONY: isort
isort:
	isort --ac $(py_sources)

# generation:

.PHONY: clean-pyc
clean-pyc:
	find hathor hathor_tests -name \*.pyc -delete
	find hathor hathor_tests -name __pycache__ -delete

.PHONY: clean-caches
clean-caches:
	rm -rf .coverage .mypy_cache .pytest_cache coverage.xml coverage_html_report

.PHONY: clean
clean: clean-pyc clean-caches

# docker:

docker_dir := .
ifdef GITHUB_REF
	docker_subtag := $(GITHUB_REF)
else
ifneq ($(wildcard .git/.*),)
	docker_subtag := $(shell git describe --tags --dirty)
else
	docker_subtag := $(shell date +'%y%m%d%H%M%S')
endif
endif
docker_tag := hathor-core:$(docker_subtag)
docker_build_arg :=
docker_build_flags :=
ifneq ($(docker_build_arg),)
	docker_build_flags +=  --build-arg $(docker_build_arg)
endif

.PHONY: docker
docker: $(docker_dir)/Dockerfile
	docker build$(docker_build_flags) -t $(docker_tag) $(docker_dir)

.PHONY: docker-push
docker-push: docker
	docker tag $(docker_tag) hathornetwork/hathor-core:$(docker_subtag)
	docker push hathornetwork/hathor-core:$(docker_subtag)

.PHONY: docker-push
docker-push-aws: docker
	docker tag $(docker_tag) 769498303037.dkr.ecr.us-east-1.amazonaws.com/fullnode:$(docker_subtag)
	docker push 769498303037.dkr.ecr.us-east-1.amazonaws.com/fullnode:$(docker_subtag)

# If you get errors similar to the one below, running `make fix-rocksdb` may fix the problem.
#
# Traceback (most recent call last):
#   File "<string>", line 1, in <module>
#   File "/<redacted>/pypoetry/virtualenvs/hathor-29FNXj3I-py3.11/lib/python3.11/site-packages/rocksdb/__init__.py", line 1, in <module>
#     from ._rocksdb import *
# ImportError: dlopen(/<redacted>/pypoetry/virtualenvs/hathor-29FNXj3I-py3.11/lib/python3.11/site-packages/rocksdb/_rocksdb.cpython-311-darwin.so, 0x0002): Library not loaded: /opt/homebrew/opt/rocksdb/lib/librocksdb.9.dylib
#   Referenced from: /<redacted>/pypoetry/virtualenvs/hathor-29FNXj3I-py3.11/lib/python3.11/site-packages/rocksdb/_rocksdb.cpython-311-darwin.so
#   Reason: tried: '/opt/homebrew/opt/rocksdb/lib/librocksdb.9.dylib' (no such file), '/System/Volumes/Preboot/Cryptexes/OS/opt/homebrew/opt/rocksdb/lib/librocksdb.9.dylib' (no such file), '/opt/homebrew/opt/rocksdb/lib/librocksdb.9.dylib' (no such file), '/opt/homebrew/Cellar/rocksdb/10.0.1/lib/librocksdb.9.dylib' (no such file), '/System/Volumes/Preboot/Cryptexes/OS/opt/homebrew/Cellar/rocksdb/10.0.1/lib/librocksdb.9.dylib' (no such file), '/opt/homebrew/Cellar/rocksdb/10.0.1/lib/librocksdb.9.dylib' (no such file)
.PHONY: fix-rocksdb
fix-rocksdb:
	poetry run pip uninstall -y rocksdb && poetry run pip install --no-binary :all: git+https://github.com/hathornetwork/python-rocksdb.git
