# Overture VPN — legacy image name

The complete VPN application has moved to **[Overture VPN](https://github.com/eukhlg/overture-vpn)**.

For new deployments, use:

```sh
docker pull eukhlg/overture-vpn:latest
# Or:
docker pull ghcr.io/eukhlg/overture-vpn:latest
```

During the naming transition, compatible releases are published under both the
`overture-vpn` and `l2tp-go` image names. Historical version tags remain available.
The new `github.com/eukhlg/l2tp-go` repository contains the independent L2TP/PPP
library; this container remains the complete application.

Existing flag-only commands, `L2TP_*` environment settings, the `l2tp-go`
executable, and `/etc/l2tp-go/server.toml` mounts remain supported. The application
now also accepts `overture-vpn server`. Client mode is planned.

See the [configuration and deployment guide](https://github.com/eukhlg/overture-vpn#configuration)
and [migration guide](https://github.com/eukhlg/overture-vpn/blob/main/migration/README.md).
