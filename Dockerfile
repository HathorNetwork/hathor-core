# based on Linux Alpine, used for building RocksDB
FROM alpine:3.9 as rocksdb_builder

RUN apk add --no-cache git
RUN git -c advice.detachedHead=false clone --branch v5.18.3 --depth 1 https://github.com/facebook/rocksdb.git
RUN apk add --no-cache zlib zlib-dev bzip2 bzip2-dev snappy snappy-dev lz4 lz4-dev cmake make g++ build-base linux-headers
RUN cd rocksdb && mkdir build && cd build && cmake -DBUILD_SHARED_LIBS=1 -DWITH_GFLAGS=0 .. && make install
# RUN cd rocksdb && make shared_lib

# based on Linux Alpine, official Python build, used for building
FROM python:3.6-alpine as builder

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
FROM python:3.6-alpine

# required runtime deps
RUN apk --no-cache add openssl libffi libstdc++
COPY --from=builder /usr/src/app/.venv/lib/python3.6/site-packages /usr/local/lib/python3.6/site-packages
COPY --from=rocksdb_builder /usr/lib64/librocksdb* /usr/lib/

# install hathor
WORKDIR /usr/src/app/
COPY hathor ./hathor

EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
