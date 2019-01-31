# based on Linux Alpine, official Python build, used for building
FROM python:3.6-alpine as builder

# required build deps
RUN apk add openssl-dev libffi-dev g++ git

# install pipenv
RUN pip install --no-cache-dir pipenv

WORKDIR /usr/src/app/
COPY Pipfile* ./

ENV PIPENV_COLORBLIND=1 \
    PIPENV_YES=1 \
    PIPENV_DONT_LOAD_ENV=1 \
    PIPENV_DONT_USE_PYENV=1 \
    PIPENV_HIDE_EMOJIS=1 \
    PIPENV_MAX_RETRIES=1 \
    PIPENV_VENV_IN_PROJECT=1
RUN pipenv --bare install --ignore-pipfile --deploy

# based on Linux Alpine, official Python build, final image
FROM python:3.6-alpine

# required runtime deps
RUN apk --no-cache add openssl libffi libstdc++
COPY --from=builder /usr/src/app/.venv/lib/python3.6/site-packages /usr/local/lib/python3.6/site-packages

# install hathor
WORKDIR /usr/src/app/
COPY hathor ./hathor

EXPOSE 40403 8080
ENTRYPOINT ["python", "-m", "hathor"]
