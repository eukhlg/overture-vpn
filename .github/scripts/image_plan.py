"""Resolve explicitly selected GitHub branches to immutable image inputs."""
import os
import re
import subprocess

REPOS = {'app': 'eukhlg/overture-vpn', 'l2tp': 'eukhlg/l2tp-go', 'ipsec': 'eukhlg/ipsec-go'}


class MissingRef(ValueError):
    pass


def feature_tag(branch):
    name = branch.removeprefix('codex/')
    slug = re.sub(r'[^a-z0-9_.-]+', '-', name.lower()).strip('.-')
    if not slug or len(slug) > 120:
        raise ValueError('Feature name must produce a nonempty image tag of at most 120 characters')
    return 'testing-' + slug


def selection(mode, branch='', release_tag='', image_name=''):
    if mode == 'release':
        if not re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', release_tag):
            raise ValueError('A numeric stable release version is required')
        return release_tag.removeprefix('v'), 'refs/tags/' + release_tag
    if mode == 'main':
        return 'testing', 'main'
    if mode != 'feature':
        raise ValueError('Unknown image mode')
    validate_branch(branch)
    if image_name and (image_name.startswith(('-', 'refs/')) or any(c.isspace() for c in image_name)):
        raise ValueError('Use a simple image name without spaces')
    return feature_tag(image_name or branch), branch


def validate_branch(branch):
    if not branch or branch.startswith(('-', 'refs/')) or any(c.isspace() for c in branch):
        raise ValueError('Enter a GitHub branch name, for example main or codex/udp-batching')


def resolve(repo, ref):
    if not ref.startswith(('refs/heads/', 'refs/tags/')):
        ref = 'refs/heads/' + ref
    subprocess.run(['git', 'check-ref-format', ref], check=True, capture_output=True)
    # No-match is distinct from network/auth failures: only a missing branch
    # permits fallback. Never silently replace a failed remote lookup with main.
    result = subprocess.run(['git', 'ls-remote', 'https://github.com/' + repo + '.git', ref, ref + '^{}'],
                            check=True, capture_output=True, text=True)
    refs = dict(line.split('\t', 1)[::-1] for line in result.stdout.splitlines())
    sha = refs.get(ref + '^{}', refs.get(ref))
    if sha is None:
        raise MissingRef(f'{repo} has no {ref}')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError(f'Invalid commit for {repo} {ref}')
    return sha


def plan(mode, branch='', release_tag='', resolve_ref=resolve,
         l2tp_branch='main', ipsec_branch='main', image_name=''):
    tag, branch = selection(mode, branch, release_tag, image_name)
    if mode == 'release':
        return dict(tag=tag, app_sha=resolve_ref(REPOS['app'], branch), app_ref=branch,
                    l2tp_sha='', l2tp_ref='pinned', ipsec_sha='', ipsec_ref='pinned')
    refs = dict.fromkeys(REPOS, 'main') if mode == 'main' else dict(app=branch, l2tp=l2tp_branch, ipsec=ipsec_branch)
    result = {'tag': tag}
    for component, repo in REPOS.items():
        ref = refs[component]
        validate_branch(ref)
        # An absent selected branch is an error; never substitute another branch.
        result[component + '_sha'] = resolve_ref(repo, ref)
        result[component + '_ref'] = ref
    return result


if __name__ == '__main__':
    mode = os.environ['IMAGE_MODE']
    branch = os.environ.get('IMAGE_BRANCH', '')
    release_tag = os.environ.get('RELEASE_TAG', '')
    selected = plan(mode, branch, release_tag,
                    l2tp_branch=os.environ.get('L2TP_BRANCH', 'main'),
                    ipsec_branch=os.environ.get('IPSEC_BRANCH', 'main'),
                    image_name=os.environ.get('IMAGE_NAME', ''))
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        for key, value in selected.items():
            print(f'{key}={value}', file=stream)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
        print('## Image: `' + selected['tag'] + '`\n', file=stream)
        print('| Component | Selected branch | Commit |\n|---|---|---|', file=stream)
        for component in REPOS:
            print(f'| {component} | `{selected[component + "_ref"]}` | `{selected[component + "_sha"] or "pinned in go.mod"}` |', file=stream)
