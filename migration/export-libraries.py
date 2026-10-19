#!/usr/bin/env python3
"""Extract library histories in fresh clones, then commit reviewed source snapshots.

Requires git-filter-repo on PATH. Never rewrites the source repository or pushes.
"""
import argparse
from pathlib import Path
import shutil
import subprocess


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-repo', type=Path, default=Path.cwd())
    parser.add_argument('--baseline', default='overture-migration-baseline')
    parser.add_argument('--l2tp-source', type=Path, required=True)
    parser.add_argument('--ipsec-source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    source = args.source_repo.resolve()
    destination = args.destination.resolve()
    snapshots = {'l2tp-go': args.l2tp_source.resolve(), 'ipsec-go': args.ipsec_source.resolve()}
    for name, snapshot in snapshots.items():
        if not (snapshot / 'go.mod').is_file():
            parser.error(f'{snapshot} must contain the reviewed {name} snapshot')
        if (destination / name).exists():
            parser.error(f'{destination / name} already exists; use a fresh destination')
    if not shutil.which('git-filter-repo'):
        parser.error('git-filter-repo is required on PATH')
    destination.mkdir(parents=True, exist_ok=True)
    for name, snapshot in snapshots.items():
        target = destination / name
        run('git', 'clone', '--no-local', '--single-branch', '--branch', args.baseline,
            str(source), str(target))
        # Keep the baseline ancestry, without publishing application tags as library releases.
        tags = subprocess.check_output(['git', 'tag'], cwd=target, text=True).splitlines()
        for tag in tags:
            run('git', 'tag', '-d', tag, cwd=target)
        paths = ['protocol/l2tp/', 'protocol/ppp/'] if name == 'l2tp-go' else ['protocol/isakmp/', 'protocol/esp/']
        server_files = ['engine', 'server', 'address_pool', 'ratelimit', 'doc'] if name == 'l2tp-go' else ['ike', 'esp', 'esp_transport']
        for stem in server_files:
            paths.extend([f'server/{stem}.go', f'server/{stem}_test.go'])
        # Preserve license/notice files if present in the source history.
        paths.extend(['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'NOTICE'])
        command = ['git-filter-repo', '--force']
        for path in paths:
            command.extend(['--path', path])
        run(*command, cwd=target)
        run('git', 'switch', '-c', 'main', cwd=target)
        # Replace the filtered tip with the reviewed independent module. Historical
        # versions of these paths remain available in its filtered ancestry.
        for path in target.iterdir():
            if path.name == '.git':
                continue
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        shutil.copytree(snapshot, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns('.git'))
        run('git', 'add', '--all', cwd=target)
        run('git', 'commit', '-m', f'Extract independent {name} module for Overture VPN', cwd=target)
        run('git', 'remote', 'add', 'origin', f'https://github.com/eukhlg/{name}.git', cwd=target)
        print(f'Prepared {name}: {target}', flush=True)


if __name__ == '__main__':
    main()
