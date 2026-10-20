"""One feature branch name selects all components; absent branches use main."""
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


def selection(mode, branch='', release_tag=''):
    if mode == 'release':
        if not re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', release_tag):
            raise ValueError('A numeric stable release version is required')
        return release_tag.removeprefix('v'), 'refs/tags/' + release_tag
    if mode == 'main':
        return 'testing', 'main'
    if mode != 'feature':
        raise ValueError('Unknown image mode')
    if not branch or branch == 'main' or branch.startswith(('-', 'refs/')) or any(c.isspace() for c in branch):
        raise ValueError('Enter a feature branch such as codex/packet-buffer-reuse')
    return feature_tag(branch), branch


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


def plan(mode, branch='', release_tag='', resolve_ref=resolve):
    tag, branch = selection(mode, branch, release_tag)
    if mode == 'release':
        return dict(tag=tag, app_sha=resolve_ref(REPOS['app'], branch), app_ref=branch,
                    l2tp_sha='', l2tp_ref='pinned', ipsec_sha='', ipsec_ref='pinned')
    result = {'tag': tag}
    matched = False
    for component, repo in REPOS.items():
        ref = branch
        try:
            sha = resolve_ref(repo, ref)
            matched = True
        except MissingRef:
            if mode == 'main':
                raise
            ref = 'main'
            sha = resolve_ref(repo, ref)
        result[component + '_sha'] = sha
        result[component + '_ref'] = ref
    if not matched:
        raise ValueError(f'No repository has feature branch {branch!r}')
    return result


if __name__ == '__main__':
    mode = os.environ['IMAGE_MODE']
    branch = os.environ.get('IMAGE_BRANCH', '')
    release_tag = os.environ.get('RELEASE_TAG', '')
    selected = plan(mode, branch, release_tag)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        for key, value in selected.items():
            print(f'{key}={value}', file=stream)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
        print('## Image: `' + selected['tag'] + '`\n', file=stream)
        print('| Component | Selected branch | Commit |\n|---|---|---|', file=stream)
        for component in REPOS:
            print(f'| {component} | `{selected[component + "_ref"]}` | `{selected[component + "_sha"] or "pinned in go.mod"}` |', file=stream)
