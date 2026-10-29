// Command ovpnlab runs the local OpenVPN test server (package ovpnlab) until
// interrupted, for testing the app on an emulator:
//
//	scripts/openvpn3-deps.sh host && scripts/ovpnlab/build-server.sh
//	go run ./cmd/ovpnlab -dir /tmp/ovpnlab -remote 10.0.2.2
//
// then import <dir>/client.ovpn in the app. 10.0.2.2 is the host as seen
// from the Android emulator.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"hybridvpn/netcore/ovpnlab"
)

func main() {
	dir := flag.String("dir", "", "work directory (required)")
	repo := flag.String("repo", "..", "repository root (for third_party/ovpnlab)")
	proto := flag.String("proto", "udp", "udp or tcp")
	port := flag.Int("port", 1194, "server port")
	remote := flag.String("remote", "127.0.0.1", "server address written into the client profile")
	user := flag.String("user", "", "require this username (with -pass)")
	pass := flag.String("pass", "", "password for -user")
	keyPass := flag.String("keypass", "", "encrypt the client's private key with this password")
	reuse := flag.Bool("reuse", false, "keep the keys and profile from an earlier run in -dir")
	flag.Parse()
	if *dir == "" {
		flag.Usage()
		os.Exit(2)
	}
	root, _ := filepath.Abs(*repo)
	openvpn, shim, err := ovpnlab.Binaries(root)
	if err != nil {
		log.Fatal(err)
	}
	abs, _ := filepath.Abs(*dir)
	lab, err := ovpnlab.Start(ovpnlab.Options{Dir: abs, OpenVPN: openvpn, Shim: shim, Proto: *proto, Port: *port,
		Remote: *remote, Username: *user, Password: *pass, KeyPassword: *keyPass, Log: os.Stderr, Reuse: *reuse})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ready: profile %s\n", filepath.Join(abs, "client.ovpn"))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	lab.Close()
}
