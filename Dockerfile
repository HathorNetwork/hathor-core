# based on Linux Alpine, official Python build, used for building
FROM python:3.6-alpine3.11 as stage1

# required build deps
RUN apk add openssl-dev libffi-dev g++ git

# install pipenv
RUN pip install --no-cache-dir pipenv

WORKDIR /usr/src/app/
COPY Pipfile* ./

RUN apk add --no-cache zlib zlib-dev bzip2 bzip2-dev snappy snappy-dev lz4 lz4-dev
RUN apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb-dev

ENV PIPENV_COLORBLIND=1 \
    PIPENV_YES=1 \
    PIPENV_DONT_LOAD_ENV=1 \
    PIPENV_DONT_USE_PYENV=1 \
    PIPENV_HIDE_EMOJIS=1 \
    PIPENV_MAX_RETRIES=1 \
    PIPENV_VENV_IN_PROJECT=1
RUN pipenv run pip install "setuptools<43"
RUN pipenv --bare install --ignore-pipfile --deploy
RUN pipenv run pip install "cython<0.30"
RUN pipenv run pip install python-rocksdb==0.7.0

# based on Linux Alpine, official Python build, used for compiling protos
FROM python:3.6-alpine3.11 as stage2

# required build deps
RUN apk add openssl-dev libffi-dev g++ git

# install pipenv
RUN pip install --no-cache-dir pipenv

WORKDIR /usr/src/app/
COPY Pipfile* ./

RUN apk add --no-cache g++ make

ENV PIPENV_COLORBLIND=1 \
    PIPENV_YES=1 \
    PIPENV_DONT_LOAD_ENV=1 \
    PIPENV_DONT_USE_PYENV=1 \
    PIPENV_HIDE_EMOJIS=1 \
    PIPENV_MAX_RETRIES=1 \
    PIPENV_VENV_IN_PROJECT=1
COPY --from=stage1 /usr/src/app/.venv /usr/src/app/.venv/
RUN pipenv --bare install --ignore-pipfile --deploy --dev

COPY Makefile ./
COPY hathor/protos ./hathor/protos/
RUN pipenv run make protos

# based on Linux Alpine, official Python build, final image
FROM python:3.6-alpine3.11

# required runtime deps
RUN apk --no-cache add openssl libffi libstdc++ graphviz
RUN apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb
COPY --from=stage1 /usr/src/app/.venv/lib/python3.6/site-packages /usr/local/lib/python3.6/site-packages
COPY --from=stage2 /usr/src/app/hathor/protos/*.py /usr/src/app/hathor/protos/

# install hathor
WORKDIR /usr/src/app/
COPY hathor ./hathor

EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
