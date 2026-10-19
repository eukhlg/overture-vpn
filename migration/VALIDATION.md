# Local migration validation

Validated on October 19, 2026.

## Source and history

- Original combined baseline: `df1853d0afd8ec6e73b1aa0ef240ec64feac31cd`.
- L2TP extraction: `794b22363d435ce53f2f18d9f6df2e11345c554a` (35 commits).
- IPsec extraction: `05ca383238686ea714d3bf79505897aa46cd8802` (27 commits).
- Each extracted library has its own Git repository, main branch, module, README,
  and test workflow. Neither library depends on the other or on Overture.
- Recovery bundles and a path/commit manifest are stored in `.migration/`.

## Checks passed

- The existing combined-project tests before the split.
- Race-enabled tests for the application, L2TP library, and IPsec library.
- Independent library tests and vet with `GOWORK=off`.
- Independent Overture tests and vet with `GOWORK=off`, using a temporary local
  Go proxy containing the exact committed library snapshots. Their checksums
  are recorded in go.sum. No library versions were published by this check.
- Linux amd64 and arm64 application builds with CGO disabled.
- Overture's `server` command and legacy flag-only invocation.
- Explicit rejection of the reserved, unimplemented `client` command.
- New configuration variable precedence and legacy fallback.
- Compose new defaults, legacy fallback, and new-variable precedence.
- Shell syntax and Git whitespace checks.

## Container checks passed

A local `overture-vpn:migration-check` image was built for the host architecture.
The temporary build used the production Dockerfile with only dependency fetching
redirected to a file proxy containing the reviewed library snapshots. Runtime
layers and startup scripts matched the prepared production image.

Disposable containers validated the new command, legacy executable and entrypoint
symlinks, old and new configuration mounts, the reserved client command, and raw
L2TP server startup and graceful shutdown. Containers used an isolated network,
no published host ports, and no added capabilities.

## Remaining release checks

Both first library tags were resolved from the public Go proxy and checksum
database, and their hashes match the reviewed snapshots. Overture passes
race-enabled tests and vet against those public releases with GOWORK=off.
The normal production Docker build must also pass using those public releases. The Docker
workflow retains both amd64 and arm64 targets and publishes new and legacy names.

The supported Windows, Linux, and macOS client interoperability matrix and
long-duration rekey behavior were not rerun against external clients during this
migration. The existing local protocol/rekey/lifecycle regression tests passed.
The original repository has been renamed to eukhlg/overture-vpn. The new public
library repositories and their first releases are published, with successful
independent GitHub CI runs. Application CI and registry publication are checked
separately during the cutover.

## Remote cutover verification

- Both independent library CI runs passed before release tagging.
- The application passed GitHub push and pull-request tests against the public library releases.
- The production multi-platform image workflow passed on the migration branch.
- Anonymous pulls of all four testing image paths returned the same index digest,
  with both linux/amd64 and linux/arm64 manifests.
- Both GHCR image packages are public and linked to the Overture application.
- Migration pull request #1 was merged with its commits retained.

The stable application release is published after the final main-branch checks.
Docker Hub description synchronization uses the existing registry credential
in GitHub Actions. During cutover this credential successfully published images
but received HTTP 403 when editing descriptions. Metadata synchronization is
therefore best effort; the prepared legacy migration notice is in docker/LEGACY.md.
