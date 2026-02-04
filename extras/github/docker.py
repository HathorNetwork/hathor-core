import re
import os
from typing import Dict

def print_output(output: Dict):
    outputs = ['{}={}\n'.format(k, v) for k, v in output.items()]
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        f.writelines(outputs)

def prep_base_version(environ: Dict):
    GITHUB_REF = environ.get('GITHUB_REF')
    GITHUB_EVENT_NAME = environ.get('GITHUB_EVENT_NAME')
    GITHUB_SHA = environ.get('GITHUB_SHA')
    GITHUB_EVENT_DEFAULT_BRANCH = environ.get('GITHUB_EVENT_DEFAULT_BRANCH')
    GITHUB_EVENT_NUMBER = environ.get('GITHUB_EVENT_NUMBER')
    GITHUB_REPOSITORY = environ.get('GITHUB_REPOSITORY')

    ref = GITHUB_REF

    # Set base_version according to the github ref type
    is_pre_release = False
    is_release = False
    is_nightly = False

    overwrite_hathor_core_version = False

    output = {}

    if GITHUB_EVENT_NAME == 'schedule':
        commit_short_sha = GITHUB_SHA[:8]
        base_version = 'nightly-' + commit_short_sha
        is_nightly = True
    elif ref.startswith('refs/tags/'):
        git_tag = ref[10:]
        base_version = git_tag.split('-', 1)[0]

        pre_release = (git_tag.split('-', 1)[1:] or [None])[0]
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
    # but we know when we should disable it for sure
    output['disable-slack-notification'] = not (is_release or is_pre_release)

    if GITHUB_REPOSITORY.lower() != 'hathornetwork/hathor-core':
        output['disable-slack-notification'] = True

    return output, base_version, is_pre_release, overwrite_hathor_core_version


def prep_tags(environ: Dict, base_version: str, is_pre_release: bool):
    MATRIX_PYTHON_IMPL = environ.get('MATRIX_PYTHON_IMPL')
    MATRIX_PYTHON_VERSION = environ.get('MATRIX_PYTHON_VERSION')

    SECRETS_DOCKERHUB_IMAGE = environ.get('SECRETS_DOCKERHUB_IMAGE')
    SECRETS_GHCR_IMAGE = environ.get('SECRETS_GHCR_IMAGE')

    GITHUB_EVENT_NAME = environ.get('GITHUB_EVENT_NAME')
    GITHUB_SHA = environ.get('GITHUB_SHA')

    import datetime
    import re

    output = {}

    # Extract default python versions from the Dockerfiles
    def extract_pyver(filename):
        for line in open(filename).readlines():
            if line.startswith('ARG PYTHON'):
                return line.split('=')[1].strip()
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
    elif GITHUB_EVENT_NAME == 'push' and not is_pre_release:
        tags.add('sha-' + GITHUB_SHA[:8])

    # Build the image list and set outputs
    output['version'] = version
    images = []
    docker_image = SECRETS_DOCKERHUB_IMAGE
    if docker_image:
        images.append(docker_image)
        output['login-dockerhub'] = 'true'
    else:
        output['login-dockerhub'] = 'false'
    ghcr_image = SECRETS_GHCR_IMAGE
    if ghcr_image:
        images.append(ghcr_image)
        output['login-ghcr'] = 'true'
    else:
        output['login-ghcr'] = 'false'
    if images and tags:
        output['tags'] = ','.join(f'{i}:{t}' for i in images for t in tags)
        output['push'] = 'true'
    else:
        output['tags'] = 'dont-push--local-only'
        output['push'] = 'false'

    output['created'] = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
    output['dockerfile'] = dockerfile

    return output


def overwrite_version(base_version: str):
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
