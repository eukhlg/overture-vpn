# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY tun ./tun
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/overture-vpn ./cmd/overture-vpn

FROM alpine:3.22
RUN apk add --no-cache ca-certificates iproute2 iptables
COPY --from=build /out/overture-vpn /usr/local/bin/overture-vpn
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/overture-entrypoint
RUN ln -s overture-vpn /usr/local/bin/l2tp-go && ln -s overture-entrypoint /usr/local/bin/l2tp-entrypoint
LABEL org.opencontainers.image.title="Overture VPN" \
      org.opencontainers.image.source="https://github.com/eukhlg/overture-vpn"
EXPOSE 1701/udp 500/udp 4500/udp
ENTRYPOINT ["/usr/local/bin/overture-entrypoint"]
