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

Feature images are built deliberately, after all component code is pushed:

1. Work on the same full branch name in each repository you change, for example
   `codex/packet-buffer-reuse`.
2. Commit and push all component changes. Pushes run code tests; library and app
   feature pushes do not request image builds.
3. In Overture's GitHub Actions, select **Build feature image**, click **Run
   workflow**, leave the workflow branch as `main`, and enter the full feature
   branch name in the single input field.
4. One build combines the latest matching branch in the app, L2TP, and IPsec. A
   component without that branch uses `main`. If no repo has the feature branch,
   the build fails instead of publishing an accidental all-main feature image.
5. After tests pass, pull `eukhlg/overture-vpn:testing-packet-buffer-reuse` from
   Docker Hub or `ghcr.io/eukhlg/overture-vpn:testing-packet-buffer-reuse`.

Tags drop the optional `codex/` prefix. Other invalid tag characters become `-`
and letters become lowercase. Use unique feature names to keep tags distinct.
Only code pushed to GitHub is included. No manual module-version bump or mapping
file is required for a feature build. Its summary shows the branch and exact
commit selected for all three components; these also appear in image labels.

**Build main and release images** is automatic: an app `main` push rebuilds
shared `testing` from all three `main` branches. Merge library features first
and the app last so that final app merge includes the library changes. Library
pushes never request images; if only libraries change, manually re-run the latest
successful main build after merging them to refresh shared `testing`.

**Publish selected image (internal)** is the shared build implementation, called
by the manual and automatic workflows. It has no independent push or dispatch
trigger. Builds for the same tag are serialized without interrupting an active
publication. There is no collection window, cross-repository dispatch, or
per-feature setup. The old app image workflow and library image-notification
workflows are disabled on GitHub so old copies in existing branches stay inert.
Independent library test workflows remain enabled.

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
