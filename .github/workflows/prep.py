import re
import os

GITHUB_REF = os.environ['GITHUB_REF'] 
GITHUB_EVENT_NAME = os.environ['GITHUB_EVENT_NAME'] 
GITHUB_SHA = os.environ['GITHUB_SHA'] 
GITHUB_EVENT_DEFAULT_BRANCH = os.environ['GITHUB_EVENT_DEFAULT_BRANCH'] 
GITHUB_EVENT_NUMBER = os.environ['GITHUB_EVENT_NUMBER'] 

MATRIX_PYTHON_IMPL = os.environ['MATRIX_PYTHON_IMPL'] 
MATRIX_PYTHON_VERSION = os.environ['MATRIX_PYTHON_VERSION'] 

SECRETS_DOCKERHUB_IMAGE = os.environ['SECRETS_DOCKERHUB_IMAGE']
SECRETS_GHCR_IMAGE = os.environ['SECRETS_GHCR_IMAGE']


def print_output(output: dict):
    for k, v in output.items():
        print(f'::set-output name={k}::{v}')


def prep_base_version():
    ref = GITHUB_REF 

    # Set base_version according to the github ref type
    is_release_candidate = False
    enable_docker_cache = True
    overwrite_hathor_core_version = False

    output = {}

    if GITHUB_EVENT_NAME == 'schedule':
        commit_short_sha = GITHUB_SHA[:8]
        base_version = 'nightly-' + commit_short_sha
        enable_docker_cache = False
        overwrite_hathor_core_version = True
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
            if re.match(r'^rc\.[0-9]{1,3}$', pre_release):
                base_version = base_version + '-' + pre_release
                is_release_candidate = True
            else:
                raise ValueError(f'Invalid Tag Value: {git_tag}')
    elif ref.startswith('refs/heads/'):
        base_version = ref[11:].replace('/', '-')
        if base_version == GITHUB_EVENT_DEFAULT_BRANCH:
            base_version = 'stable'
    elif ref.startswith('refs/pull/'):
        base_version = 'pr-' + GITHUB_EVENT_NUMBER
    else:
        base_version = 'noop'

    output['enable-docker-cache'] = 'true' if enable_docker_cache else 'false'

    return output, base_version, is_release_candidate, overwrite_hathor_core_version


def prep_tags(base_version, is_release_candidate):
    import datetime
    import re

    output = {}

    # Extract default python versions from the Dockerfiles
    def extract_pyver(filename):
        for line in open(filename).readlines():
            if line.startswith('ARG PYTHON'):
                return line.split('=')[1].strip()
    dockerfile_cpython = 'Dockerfile'
    dockerfile_pypy = 'Dockerfile.pypy'
    default_python = 'python' + extract_pyver(dockerfile_cpython)
    default_pypy = 'pypy' + extract_pyver(dockerfile_pypy)

    # Set which Dockerfile to use based on the versions matrix
    if MATRIX_PYTHON_IMPL == 'pypy':
        dockerfile = dockerfile_pypy
        suffix = 'pypy' + MATRIX_PYTHON_VERSION
    else:
        dockerfile = dockerfile_cpython
        suffix = 'python' + MATRIX_PYTHON_VERSION

    # Build the tag list

    tags = set()

    # We don't want a tag with a python suffix for release-candidates
    if is_release_candidate:
        version = base_version
    else:
        version = base_version + '-' + suffix
        tags.add(version)

    if suffix == default_python:
        tags.add(base_version)
        output['notify-slack'] = base_version
    elif suffix == default_pypy:
        tags.add(base_version + '-pypy')

    # Check if this is a stable release
    if re.match(r'^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', base_version):
        minor = base_version.rpartition('.')[0]
        tags.add(minor + '-' + suffix)
        if suffix == default_python:
            tags.add('latest')
    elif GITHUB_EVENT_NAME == 'push' and not is_release_candidate:
        tags.add('sha-' + '${{ github.sha }}'[:8])

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
        output['logic-ghcr'] = 'true'
    else:
        output['logic-ghcr'] = 'false'
    if images and tags:
        output['tags'] = ','.join(f'{i}:{t}' for i in images for t in tags)
        output['push'] = 'true'
    else:
        output['tags'] = 'dont-push--local-only'
        output['push'] = 'false'

    output['created'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    output['dockerfile'] = dockerfile

    return output


def overwrite_version(version: str):
    with open('BUILD_VERSION', 'w') as file:
        file.write(version + '\n')


if __name__ == '__main__':
    output, base_version, is_release_candidate, overwrite_hathor_core_version = prep_base_version()
    print_output(output)

    output = prep_tags(base_version, is_release_candidate)
    print_output(output)

    if overwrite_hathor_core_version:
        overwrite_version(base_version)
