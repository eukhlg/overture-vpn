package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"l2tp-go/server"
)

func main() {
	listen := flag.String("listen", ":1701", "UDP address on which to listen")
	hostname := flag.String("hostname", "l2tp-go", "L2TP host name advertised to peers")
	flag.Parse()

	s, err := server.Listen(*listen, server.Config{HostName: *hostname})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	s.HandleData = func(_ context.Context, frame server.DataFrame) error {
		log.Printf("PPP frame: peer=%s tunnel=%d session=%d protocol=%#x bytes=%d", frame.Peer, frame.TunnelID, frame.Session.LocalID, frame.PPP.Protocol, len(frame.PPP.Payload))
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("L2TP listener started on %s (unencrypted; IPsec transport is not implemented yet)", s.Conn.LocalAddr())
	if err := s.Serve(ctx); err != nil {
		log.Fatal(err)
	}
}
