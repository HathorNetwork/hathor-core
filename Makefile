
.PHONY: all
all: tests pep8

.PHONY: tests
tests:
	pytest --cov=hathor --cov-fail-under=85 -p no:warnings ./tests

.PHONY: pep8
pep8:
	flake8 hathor/ tests/ tools/ *.py

.PHONY: coverage report
cov_report:
	pytest --cov-report=term --cov-report=html --cov=hathor --cov-fail-under=85 -p no:warnings ./tests

proto_dir = ./hathor/protos
proto_srcs = $(wildcard $(proto_dir)/*.proto)
proto_outputs = $(patsubst %.proto,%_pb2.py,$(proto_srcs)) $(patsubst %.proto,%_pb2_grpc.py,$(proto_srcs))

# all proto_srcs are added as deps so we a change on any of them triggers all to be rebuilt
%_pb2.py %_pb2_grpc.py: %.proto $(proto_srcs)
	python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. $<

.PHONY: protos
protos: $(proto_outputs)

.PHONY:
clean:
	rm -f $(proto_outputs)
