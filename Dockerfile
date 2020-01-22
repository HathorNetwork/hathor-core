# based on Linux Alpine, used for building RocksDB
FROM alpine:3.9 as rocksdb_builder

RUN apk add --no-cache git
RUN git -c advice.detachedHead=false clone --branch v5.18.3 --depth 1 https://github.com/facebook/rocksdb.git
RUN apk add --no-cache zlib zlib-dev bzip2 bzip2-dev snappy snappy-dev lz4 lz4-dev cmake make g++ build-base linux-headers
RUN cd rocksdb && mkdir build && cd build && cmake -DBUILD_SHARED_LIBS=1 -DWITH_GFLAGS=0 .. && make install
# RUN cd rocksdb && make shared_lib

# based on Linux Alpine, official Python build, used for building
FROM python:3.6-alpine3.9 as builder

# required build deps
RUN apk add openssl-dev libffi-dev g++ git

# install pipenv
RUN pip install --no-cache-dir pipenv

WORKDIR /usr/src/app/
COPY Pipfile* ./

RUN apk add --no-cache zlib zlib-dev bzip2 bzip2-dev snappy snappy-dev lz4 lz4-dev
COPY --from=rocksdb_builder /usr/include/rocksdb /usr/include/rocksdb
COPY --from=rocksdb_builder /usr/lib64/librocksdb* /usr/lib64/

ENV PIPENV_COLORBLIND=1 \
    PIPENV_YES=1 \
    PIPENV_DONT_LOAD_ENV=1 \
    PIPENV_DONT_USE_PYENV=1 \
    PIPENV_HIDE_EMOJIS=1 \
    PIPENV_MAX_RETRIES=1 \
    PIPENV_VENV_IN_PROJECT=1
RUN pipenv --bare install --ignore-pipfile --deploy
RUN pipenv run pip install python-rocksdb==0.7.0

# based on Linux Alpine, official Python build, final image
FROM python:3.6-alpine3.9

ENV BRANCH_SELECTED='fix/merged-mining-tidbits'
ENV BTC_RPC=http://user:password@bitcoind-testnet:18332
ENV HATHOR_BC=hathor-bc:8001
ENV STRATUM_PORT=40403
ENV STATUS_PORT=8001
ENV HATHOR_WALLET=H8Y4ET5cMSyBVdRxYKSvHi4YzrN9sJS4an
ENV PEER_ID=/opt/peer_id.json

# required runtime deps
RUN apk --no-cache add openssl libffi libstdc++ graphviz
COPY --from=builder /usr/src/app/.venv/lib/python3.6/site-packages /usr/local/lib/python3.6/site-packages
COPY --from=rocksdb_builder /usr/lib64/librocksdb* /usr/lib/

# install hathor
WORKDIR /usr/src/app/
COPY hathor ./hathor

EXPOSE 40403 8080 8082
ENTRYPOINT ["python", "-m", "hathor run_merged_mining --port 8082 --hathor-stratum ${HATHOR_BC} --bitcoin-rpc ${BTC_RPC} --hathor-address ${HATHOR_WALLET}"]
