# Overture VPN migration

The application checkout lives in `app/` and retains its complete Git history.
The `l2tp-go/` and `ipsec-go/` checkouts are its siblings. Each directory is an
independent Git repository, with its own branches and Go module. The containing
`overture-vpn/` workspace directory has no Git repository.

## Local development

```text
overture-vpn/
├── go.work
├── overture-vpn.code-workspace
├── app/
├── l2tp-go/
└── ipsec-go/
```

The local `go.work` joins all three modules. From the workspace directory:

```sh
go test ./app/... ./l2tp-go/... ./ipsec-go/...
go build -o app/overture-vpn ./app/cmd/overture-vpn
cd app
./overture-vpn server --config ./overture-vpn.toml
```

Open `overture-vpn.code-workspace` from the containing workspace directory in VS
Code. It exposes the three repositories separately for staging, committing,
branching, and pushing. The application's module path remains
`github.com/eukhlg/overture-vpn`; its local directory name is `app`.

For a fresh checkout:

```sh
mkdir overture-vpn
cd overture-vpn
git clone https://github.com/eukhlg/overture-vpn.git app
git clone https://github.com/eukhlg/l2tp-go.git l2tp-go
git clone https://github.com/eukhlg/ipsec-go.git ipsec-go
go work init ./app ./l2tp-go ./ipsec-go
```

Add the three folders to a VS Code multi-root workspace and save it beside
`go.work`. Both workspace files are local development files outside the Git
repositories. Local library edits are used immediately. Application releases
remain pinned to published versions in `app/go.mod`; do not commit local
`replace` directives to any module's `go.mod`.

Each library builds and tests independently with `GOWORK=off go test ./...`.
Overture's independent build requires the new library releases listed in go.mod:
[l2tp-go v0.3.0](https://github.com/eukhlg/l2tp-go/releases/tag/v0.3.0) and
[ipsec-go v0.1.0](https://github.com/eukhlg/ipsec-go/releases/tag/v0.1.0). Both are
published. The public Go proxy and checksum database match the reviewed source
snapshots; Overture passes its independent tests against those public releases.

## History and recovery

The baseline tag is `overture-migration-baseline` at the last combined commit.
A complete pre-migration Git bundle is stored at `../.migration/original-before-overture.bundle`
(and initially at `/tmp/l2tp-before-overture.bundle`). Each prepared repository
also has a Git bundle in the workspace-level `.migration/` directory. See [validation results](VALIDATION.md).
The original application's commits and old version tags are retained. Each
library's filtered ancestors have different commit hashes; its history includes
only the relevant protocol/runtime paths, followed by the extraction commit.
Old application tags are deliberately absent from the library repositories.

`export-libraries.py` documents and automates the extraction from fresh clones.
It accepts reviewed library source snapshots, a source repository, a baseline
ref, and an empty destination. It never rewrites the source repository or pushes.
The sibling `../l2tp-go/` and `../ipsec-go/` repositories can be used as its source snapshots if
another export is needed. It requires git-filter-repo on PATH.

The source had no tracked license file at extraction time. No new license was
invented as part of this migration; license policy remains an owner decision.

## Remote cutover order

1. Back up the prepared application and library refs.
2. Rename `eukhlg/l2tp-go` to `eukhlg/overture-vpn` on GitHub. This retains the
   original issues, pull requests, branches, tags, and complete application history.
3. Update this checkout's origin to `https://github.com/eukhlg/overture-vpn.git`.
4. Create new `eukhlg/l2tp-go` and `eukhlg/ipsec-go` repositories. Reusing the old
   l2tp-go name replaces GitHub's redirect, so announce the move before this step.
5. Push only each prepared library's `main` branch. Verify its independent CI,
   then tag and publish `v0.3.0` / `v0.1.0`, respectively. Do not push application
   tags into the new library repositories.
6. Resolve both versions from the public Go proxy; run `GOWORK=off go mod tidy`,
   tests, vet, and the Overture build against those published versions. Verify
   the resulting library checksums match the reviewed snapshots.
7. Push the Overture migration branch and review/merge it into the application's
   default branch. Verify CI and the supported OS-client interoperability matrix.
8. Prepare registry access and publish the first compatible Overture release.

Remote renames, repository creation, releases, and image pushes are not performed
by the local export script. Avoid force-pushing the original application's history.

## Container transition

The Overture workflow publishes one amd64/arm64 build to four image paths:

- `docker.io/eukhlg/overture-vpn`
- `ghcr.io/eukhlg/overture-vpn`
- `docker.io/eukhlg/l2tp-go` (temporary compatibility publication)
- `ghcr.io/eukhlg/l2tp-go` (temporary compatibility publication)

Before its first run, create the new Docker Hub repository, grant the Docker Hub
token write access to both names, make the new GHCR package public, and ensure
both GHCR packages grant the Overture repository's workflow write access. Link
both packages to the application; the old package should not follow the newly
created L2TP library repository. Update registry descriptions with the migration
notice. Description synchronization is best effort: a token that can push images
may still be unable to edit repository metadata. In that case, use Docker Hub
to set the descriptions manually. Existing versioned images must remain available.

Image builds run after pushes to any branch in all three repositories:

- A push/merge to `main` publishes shared `testing`, selecting the latest `main`
  commits from all three repositories at build planning time.
- A feature/fix branch push publishes `testing-<branch>`, using that exact pushed
  commit and `main` from the other two repositories. Simple branch names such as
  `new-auth` produce `testing-new-auth`. Names needing normalization (such as
  `feature/auth`), or truncation, get a short hash suffix to prevent collisions.
- Each image tag has its own build concurrency group. A newer build for the same
  tag cancels an older in-progress build; different feature tags and shared
  `testing` do not cancel each other. Tests must pass before publication.

For a feature spanning multiple repositories, open Overture's **Build and publish
Overture VPN images** workflow in GitHub Actions and select **Run workflow** on
`main`. Supply a feature name and explicitly set `app_ref`, `l2tp_ref`, and
`ipsec_ref` to the branches to combine (each defaults to `main`). For example,
feature `auth-integration`, application `auth-ui`, L2TP `auth-ppp`, and IPsec
`auth-ike` publish `testing-auth-integration`. Re-run this combined build after
further feature changes. Automatic branch builds combine only the triggering
feature with the other repositories' `main`; use a distinct combined feature
name to keep that image separate from automatic branch images. No branch names
are inferred across repositories. Missing branches fail the build.

After testing a feature image, merge each participating branch into its repo's
`main`. These merges rebuild shared `testing` from all three `main` branches.

Libraries send a `module-push` repository dispatch containing their repository,
branch name, and exact commit to Overture, using their encrypted
`OVERTURE_DISPATCH_TOKEN` secret. This credential needs repository dispatch
permission in `eukhlg/overture-vpn` (contents write for a fine-grained token).
Rotate these secrets when the credential expires. Keep feature branches up to
date with `main` so they contain the current notification/build workflows.

The selected application and library commits are resolved before checkout and
recorded in the workflow summary and image labels. Testing dependency versions
are written only to the build's temporary `go.mod`.

Stable images are published only when an Overture GitHub release is published,
using its tag and the library versions pinned in that application commit.
Numeric and v-prefixed tags are accepted (for example `0.4.0` or `v0.4.0`). The
version must exceed previous stable releases. Successful builds publish the
numeric version and `latest`; a tag push alone does not publish stable images.
Library releases do not change stable application images.

Compatibility is retained for flag-only server invocations, the `/usr/local/bin/l2tp-go`
executable, `/usr/local/bin/l2tp-entrypoint`, L2TP_* server environment overrides,
and `/etc/l2tp-go/server.toml` mounts. OVERTURE_CONFIG takes precedence over
L2TP_CONFIG; an explicit --config takes precedence over both. Compose accepts
OVERTURE_IMAGE and OVERTURE_CONFIG_FILE, falling back to their L2TP_* names when
unset. Its service remains named `l2tp` to keep existing operational commands.
Do not add new Compose variables to an old .env file until its intended image and
config values have been migrated, as the new names take precedence.

Retire old-name updates only after announcing a final supported legacy release.
Keep all historical version tags. Client mode is reserved but not implemented;
it exits explicitly rather than starting a server.
