# l2tp-go

A lightweight Go L2TPv2 server under active development. The current server
supports raw (unencrypted) L2TP, PPP LCP, PAP authentication, IPCP, IPv4, and a
native TUN data path on Linux and macOS.

IPsec is not implemented yet. PAP credentials and all traffic are exposed on
the network when the server is used without IPsec; use raw mode only on a
trusted test network.

## Run with TUN routing

Build the server:

```sh
go build -o l2tp-go ./cmd/l2tp-go
```

Set the password through the environment rather than a command-line argument:

```sh
export L2TP_PASSWORD='replace-me'
```

Linux:

```sh
sudo -E ./l2tp-go \
  -tun -tun-name l2tp0 -tun-prefix 10.0.0.1/24 \
  -server-ip 10.0.0.1 -client-ip 10.0.0.2 -username vpn
```

macOS (`-tun-name` may be omitted to select an available `utun`):

```sh
sudo -E ./l2tp-go \
  -tun -tun-prefix 10.0.0.1/24 \
  -server-ip 10.0.0.1 -client-ip 10.0.0.2 -username vpn
```

The process creates the native interface, configures its address and MTU,
forwards client packets into it, reads return packets, and sends those packets
back through the matching PPP session. It brings the interface down during a
clean shutdown.

Host IP forwarding and internet NAT are deliberately not changed. Enable them
separately using the host firewall/router policy appropriate for the machine.
The current CLI assigns one fixed client address and is intended for a single
test client; the routing module itself can track multiple distinct addresses.

## Tests

```sh
go test ./...
go test -race ./...
```

Native TUN creation is an opt-in privileged integration test:

```sh
sudo go test -tags=integration ./tun -run TestOpenNativeDevice -v
```
