# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import datetime
import os
import re
from collections.abc import Mapping


def print_output(output: Mapping[str, str]) -> None:
    outputs = ['{}={}\n'.format(k, v) for k, v in output.items()]
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.writelines(outputs)


def prep_base_version(environ: Mapping[str, str]) -> tuple[dict[str, str], str, bool, bool]:
    GITHUB_REF = environ.get('GITHUB_REF', '')
    GITHUB_EVENT_NAME = environ.get('GITHUB_EVENT_NAME', '')
    GITHUB_SHA = environ.get('GITHUB_SHA', '')
    GITHUB_EVENT_DEFAULT_BRANCH = environ.get('GITHUB_EVENT_DEFAULT_BRANCH', '')
    GITHUB_EVENT_NUMBER = environ.get('GITHUB_EVENT_NUMBER', '')
    GITHUB_REPOSITORY = environ.get('GITHUB_REPOSITORY', '')

    ref = GITHUB_REF

    # Set base_version according to the github ref type
    is_pre_release = False
    is_release = False
    is_nightly = False

    overwrite_hathor_core_version = False

    output: dict[str, str] = {}

    if GITHUB_EVENT_NAME == 'schedule':
        commit_short_sha = GITHUB_SHA[:8]
        base_version = 'nightly-' + commit_short_sha
        is_nightly = True
    elif ref.startswith('refs/tags/'):
        git_tag = ref[10:]
        # `v0.53.0-rc.1` splits into `v0.53.0` and `rc.1`, `v0.53.0` leaves an empty pre-release
        base_version, _, pre_release = git_tag.partition('-')
        overwrite_hathor_core_version = True
        # This will be used to check against the versions in our source files
        check_version = base_version[1:]
        output['check-version'] = check_version

        # Check if this is a release-candidate
        if pre_release:
            if re.match(r'^(rc|alpha|beta)\.[0-9]{1,3}$', pre_release):
                base_version = base_version + '-' + pre_release
                is_pre_release = True
            else:
                raise ValueError(f'Invalid Tag Value: {git_tag}')
        else:
            is_release = True
    elif ref.startswith('refs/heads/'):
        base_version = ref[11:].replace('/', '-')
        if base_version == GITHUB_EVENT_DEFAULT_BRANCH:
            base_version = 'stable'
    elif ref.startswith('refs/pull/'):
        base_version = 'pr-' + GITHUB_EVENT_NUMBER
    else:
        base_version = 'noop'

    overwrite_hathor_core_version = is_release or is_pre_release or is_nightly
    # We don't know for sure at this point in which cases we should enable Slack notification,
    # but we know when we should disable it for sure.
    # NOTE: these are lowercase strings, not bools, because the workflow compares them against 'false'
    output['disable-slack-notification'] = 'false' if (is_release or is_pre_release) else 'true'

    if GITHUB_REPOSITORY.lower() != 'hathornetwork/hathor-core':
        output['disable-slack-notification'] = 'true'

    return output, base_version, is_pre_release, overwrite_hathor_core_version


def prep_tags(environ: Mapping[str, str], base_version: str, is_pre_release: bool) -> dict[str, str]:
    MATRIX_PYTHON_VERSION = environ.get('MATRIX_PYTHON_VERSION', '')

    SECRETS_DOCKERHUB_IMAGE = environ.get('SECRETS_DOCKERHUB_IMAGE', '')
    SECRETS_GHCR_IMAGE = environ.get('SECRETS_GHCR_IMAGE', '')

    GITHUB_EVENT_NAME = environ.get('GITHUB_EVENT_NAME', '')
    GITHUB_SHA = environ.get('GITHUB_SHA', '')

    output: dict[str, str] = {}

    # Extract default python versions from the Dockerfiles
    def extract_pyver(filename: str) -> str:
        with open(filename) as f:
            for line in f:
                if line.startswith('ARG PYTHON'):
                    return line.split('=')[1].strip()
        raise ValueError(f'Could not find an `ARG PYTHON` line in {filename}')
    dockerfile = 'Dockerfile'
    default_python = 'python' + extract_pyver(dockerfile)
    suffix = 'python' + MATRIX_PYTHON_VERSION

    # Build the tag list

    tags = set()

    # Always include -python{Version} suffix variant
    version = base_version + '-' + suffix
    tags.add(version)

    if suffix == default_python:
        tags.add(base_version)
        output['slack-notification-version'] = base_version

    # Check if this is a stable release
    if re.match(r'^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', base_version):
        minor = base_version.rpartition('.')[0]
        tags.add(minor + '-' + suffix)
        if suffix == default_python:
            tags.add('latest')
    elif GITHUB_EVENT_NAME == 'push' and not is_pre_release and suffix == default_python:
        tags.add('sha-' + GITHUB_SHA[:8])

    # Build the image list and set outputs
    output['version'] = version
    # Never publish from a pull request. The docker workflow has no `pull_request` trigger today, but if one is ever
    # added, pull requests from a branch of this repository would see the registry secrets and start publishing
    # `pr-<number>` tags to the production registries
    is_pull_request = GITHUB_EVENT_NAME in ('pull_request', 'pull_request_target')
    images = []
    docker_image = '' if is_pull_request else SECRETS_DOCKERHUB_IMAGE
    if docker_image:
        images.append(docker_image)
        output['login-dockerhub'] = 'true'
    else:
        output['login-dockerhub'] = 'false'
    ghcr_image = '' if is_pull_request else SECRETS_GHCR_IMAGE
    if ghcr_image:
        images.append(ghcr_image)
        output['login-ghcr'] = 'true'
    else:
        output['login-ghcr'] = 'false'
    output['repositories'] = ','.join(images)
    if images and tags:
        output['tags'] = ','.join(f'{i}:{t}' for i in images for t in tags)
        output['push'] = 'true'
    else:
        output['tags'] = 'dont-push--local-only'
        output['push'] = 'false'

    output['created'] = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
    output['dockerfile'] = dockerfile

    return output


def overwrite_version(base_version: str) -> None:
    with open('BUILD_VERSION', 'w') as file:
        if base_version.startswith('v'):
            base_version = base_version[1:]
        file.write(base_version)


if __name__ == '__main__':
    output, base_version, is_pre_release, overwrite_hathor_core_version = prep_base_version(os.environ)
    print_output(output)

    output = prep_tags(os.environ, base_version, is_pre_release)
    print_output(output)

    if overwrite_hathor_core_version:
        overwrite_version(base_version)
