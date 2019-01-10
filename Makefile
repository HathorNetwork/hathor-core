py_sources = hathor/ tests/ tools/ $(wildcard *.py)

.PHONY: all
all: check tests

# testing:

.PHONY: tests
tests:
	pytest --cov=hathor/cli/ --cov-config=.coveragerc_full --cov-fail-under=70 -p no:warnings ./tests/cli/
	pytest --cov-report=term --cov-report=html --cov=hathor --cov-fail-under=95 -p no:warnings ./tests

.PHONY: full_tests
full_tests:
	pytest --cov-report=term --cov-report=html --cov=hathor --cov-fail-under=90 --cov-config=.coveragerc_full -p no:warnings ./tests

# checking:

.PHONY: mypy
mypy: ./hathor
	mypy $^

.PHONY: flake8
flake8: $(py_sources)
	flake8 $^

.PHONY: isort-check
isort-check: $(py_sources)
	isort -ac -rc --check-only $^

.PHONY: check
check: flake8 isort-check mypy

# formatting:

.PHONY: fmt
fmt: yapf isort

.PHONY: yapf
yapf: $(py_sources)
	yapf -rip $^ -e \*_pb2.py,\*_pb2_grpc.py

.PHONY: isort
isort: $(py_sources)
	isort -ac -rc $^

# generation:

proto_dir = ./hathor/protos
proto_srcs = $(wildcard $(proto_dir)/*.proto)
proto_outputs = $(patsubst %.proto,%_pb2.py,$(proto_srcs)) $(patsubst %.proto,%_pb2_grpc.py,$(proto_srcs)) $(patsubst %.proto,%_pb2.pyi,$(proto_srcs))

# all proto_srcs are added as deps so we a change on any of them triggers all to be rebuilt
%_pb2.pyi %_pb2.py %_pb2_grpc.py: %.proto $(proto_srcs)
	python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. --mypy_out=. $<

.PHONY: protos
protos: $(proto_outputs)

# cleaning:

.PHONY:
clean:
	rm -f $(proto_outputs)
