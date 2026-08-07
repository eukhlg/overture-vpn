# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY protocol ./protocol
COPY server ./server
COPY tun ./tun
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/l2tp-go ./cmd/l2tp-go

FROM alpine:3.22
RUN apk add --no-cache ca-certificates iproute2 iptables
COPY --from=build /out/l2tp-go /usr/local/bin/l2tp-go
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/l2tp-entrypoint
EXPOSE 1701/udp
ENTRYPOINT ["/usr/local/bin/l2tp-entrypoint"]
