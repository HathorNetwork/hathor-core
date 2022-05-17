# before changing these variables, make sure the tag $PYTHON-alpine$ALPINE exists first
# list of valid tags hese: https://hub.docker.com/_/python
ARG PYTHON=3.9
ARG DEBIAN=bullseye

# stage-0: copy pyproject.toml/poetry.lock and install the production set of dependencies
FROM python:$PYTHON-slim-$DEBIAN as stage-0
ARG PYTHON
# install runtime first deps to speedup the dev deps and because layers will be reused on stage-1
RUN apt-get -qy update
RUN apt-get -qy install libssl1.1 graphviz librocksdb6.11
# dev deps for this build start here
RUN apt-get -qy install libssl-dev libffi-dev build-essential zlib1g-dev libbz2-dev libsnappy-dev liblz4-dev librocksdb-dev cargo git pkg-config
# install all deps in a virtualenv so we can just copy it over to the final image
RUN pip --no-input --no-cache-dir install --upgrade pip wheel poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
WORKDIR /app/
COPY pyproject.toml poetry.lock  ./
RUN poetry install -n -E sentry --no-root --no-dev
COPY hathor ./hathor
COPY README.md ./
RUN poetry build -f wheel
RUN poetry run pip install dist/hathor-*.whl

# finally: use production .venv from before
# lean and mean: this image should be about ~50MB, would be about ~470MB if using the whole stage-1
FROM python:$PYTHON-slim-$DEBIAN
ARG PYTHON
RUN apt-get -qy update
RUN apt-get -qy install libssl1.1 graphviz librocksdb6.11
COPY --from=stage-0 /app/.venv/lib/python${PYTHON}/site-packages/ /usr/local/lib/python${PYTHON}/site-packages/
EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
