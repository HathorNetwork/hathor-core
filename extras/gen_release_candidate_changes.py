#!/usr/bin/env python
"""
This script finds all PRs that have been merged into the `master` branch but not into the `release-candidate` branch in a given GitHub repository.

Usage:

    ./extras/gen_release_candidate_changes.py

Example output:

```
- #701
- #697
- #686
```
"""

import yaml
import os
import requests

BASE_API_URL = 'https://api.github.com'
REPO = 'HathorNetwork/hathor-core'


def get_gh_token():
    config_path = os.path.expanduser('~/.config/gh/hosts.yml')

    if not os.path.exists(config_path):
        print("GitHub CLI configuration not found. Please authenticate with 'gh auth login'.")
        exit(1)

    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    token = config['github.com']['oauth_token']
    return token


def get_headers(token):
    return {'Authorization': f'token {token}'}


def get_commits_ahead(base, compare, token):
    response = requests.get(
        f'{BASE_API_URL}/repos/{REPO}/compare/{base}...{compare}',
        headers=get_headers(token)
    )
    data = response.json()
    return [commit['sha'] for commit in data['commits']]


def get_pr_for_commit(commit, token):
    response = requests.get(
        f'{BASE_API_URL}/repos/{REPO}/commits/{commit}/pulls',
        headers=get_headers(token),
        params={'state': 'all'}
    )
    data = response.json()
    if data:
        return data[0]['number']
    return None


def get_new_prs_in_master(token):
    commits = get_commits_ahead('release-candidate', 'master', token)
    prs = []
    for commit in commits:
        pr = get_pr_for_commit(commit, token)
        if pr and pr not in prs:
            prs.append(pr)
    return prs


if __name__ == '__main__':
    token = get_gh_token()
    prs = get_new_prs_in_master(token)
    for pr in prs:
        print(f'- #{pr}')
