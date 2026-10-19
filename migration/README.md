# Overture VPN migration

The original checkout becomes the Overture application and retains its complete
Git history. The local library repositories are staged at `.migration/l2tp-go`
and `.migration/ipsec-go`, each on `main`, with independently filtered history
and a final extraction commit. They are separate Git repositories, not submodules.
The untracked `benchmarks/` directory was left in place.

## Local development

The ignored `go.work` joins the application and the two local library checkouts.

```sh
go test ./... ./.migration/l2tp-go/... ./.migration/ipsec-go/...
go build -o overture-vpn ./cmd/overture-vpn
./overture-vpn server --config ./overture-vpn.toml
```

Once the repositories are published, developers can clone the three repositories
as siblings and create an untracked workspace with `go work init . ../l2tp-go
../ipsec-go`. Until the first library releases exist, explicit workspace replacements
for the planned versions may be needed. Do not commit local `replace` directives
to any module's go.mod.

Each library builds and tests independently with `GOWORK=off go test ./...`.
Overture's independent build requires the new library releases listed in go.mod:
`l2tp-go v0.3.0` and `ipsec-go v0.1.0`. They are planned versions, not claims that
those versions are already published. Do not publish the app or its containers
before these exact source snapshots are released and their checksums verified.

## History and recovery

The baseline tag is `overture-migration-baseline` at the last combined commit.
A complete pre-migration Git bundle is stored at `.migration/original-before-overture.bundle`
(and initially at `/tmp/l2tp-before-overture.bundle`). Each prepared repository
also has a Git bundle in `.migration/`. See [validation results](VALIDATION.md).
The original application's commits and old version tags are retained. Each
library's filtered ancestors have different commit hashes; its history includes
only the relevant protocol/runtime paths, followed by the extraction commit.
Old application tags are deliberately absent from the library repositories.

`export-libraries.py` documents and automates the extraction from fresh clones.
It accepts reviewed library source snapshots, a source repository, a baseline
ref, and an empty destination. It never rewrites the source repository or pushes.
The prepared `.migration` repositories can be used as its source snapshots if
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
notice. Existing versioned images must remain available.

Both numeric and v-prefixed application release tags are accepted. Libraries
have test workflows only and never publish the application image. Branch builds
still use `testing`; releases use their semantic version and `latest`.

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
