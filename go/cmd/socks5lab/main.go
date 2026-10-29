// Command socks5lab runs a local SOCKS5 proxy (CONNECT and UDP ASSOCIATE,
// tailscale.com/net/socks5) that logs every request, for testing the app on an
// emulator:
//
//	go run ./cmd/socks5lab -listen 0.0.0.0:1080 -user alice -pass secret
//
// then add proxy 10.0.2.2:1080 in the app. 10.0.2.2 is the host as seen from
// the Android emulator. It listens only where told; don't expose it.
package main

import (
	"context"
	"flag"
	"log"
	"net"

	"tailscale.com/net/socks5"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "address to listen on")
	user := flag.String("user", "", "require this username (with -pass)")
	pass := flag.String("pass", "", "password for -user")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 on %s (auth: %v)", ln.Addr(), *user != "")
	srv := &socks5.Server{
		Logf:     log.Printf,
		Username: *user,
		Password: *pass,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("%s %s", network, addr)
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	log.Fatal(srv.Serve(ln))
}
