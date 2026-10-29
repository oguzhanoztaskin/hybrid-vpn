// Command tailnetlab runs offline test tailnets for exercising HybridVPN's
// tailnet transports on the Android emulator, without Tailscale accounts.
//
//	tailnetlab control -tailnets personal,work           # on the host
//	tailnetlab peer -control http://10.0.2.2:PORT -name personal   # on the emulator (adb shell)
//
// control runs, per tailnet, upstream's test coordination server, a DERP
// relay and a STUN server, all bound to 127.0.0.1 and advertised as
// 10.0.2.2 (the emulator's alias for host loopback): nothing listens on the
// LAN. peer joins one tailnet and answers TCP :8080 and :8081 with the
// tailnet's name, standing in for a remote machine. Test tool only.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"

	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/logtail"
	"tailscale.com/net/stunserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	envknob.SetNoLogsNoSupport()
	logtail.Disable()
	if len(os.Args) < 2 {
		log.Fatal("usage: tailnetlab control|peer [flags]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	names := fs.String("tailnets", "personal,work", "control: tailnet names")
	advertise := fs.String("advertise", "10.0.2.2", "control: address clients use to reach this host")
	controlURL := fs.String("control", "", "peer: control URL")
	name := fs.String("name", "", "peer: tailnet name, also the banner")
	dir := fs.String("dir", "", "peer: state directory (default /data/local/tmp/tailnetlab-<name>)")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "control":
		runControl(strings.Split(*names, ","), *advertise)
	case "peer":
		if *dir == "" {
			*dir = "/data/local/tmp/tailnetlab-" + *name
		}
		runPeer(*controlURL, *name, *dir)
	default:
		log.Fatalf("unknown mode %q", os.Args[1])
	}
}

func runControl(names []string, advertise string) {
	for _, n := range names {
		derpPort, stunPort := startDERPAndSTUN()
		ctl := &testcontrol.Server{
			DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
				1: {RegionID: 1, RegionCode: "lab", Nodes: []*tailcfg.DERPNode{{
					Name: "lab1", RegionID: 1, HostName: advertise, IPv4: advertise, IPv6: "none",
					DERPPort: derpPort, STUNPort: stunPort, STUNTestIP: advertise, InsecureForTests: true,
				}}},
			}},
			DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
			MagicDNSDomain: n + ".lab.ts.net",
			Logf:           logger.Discard,
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatal(err)
		}
		go http.Serve(ln, ctl)
		port := ln.Addr().(*net.TCPAddr).Port
		json.NewEncoder(os.Stdout).Encode(map[string]any{"tailnet": n, "control_url": fmt.Sprintf("http://%s:%d", advertise, port)})
	}
	log.Print("tailnetlab: control servers running; Ctrl-C to stop")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}

func startDERPAndSTUN() (derpPort, stunPort int) {
	d := derpserver.New(key.NewNode(), logger.Discard)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(derpserver.Handler(d))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	srv.Config.ErrorLog = logger.StdLogger(logger.Discard)
	srv.StartTLS()
	stun := stunserver.New(context.Background())
	if err := stun.Listen("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	go stun.Serve()
	return ln.Addr().(*net.TCPAddr).Port, stun.LocalAddr().(*net.UDPAddr).Port
}

func runPeer(controlURL, name, dir string) {
	s := &tsnet.Server{Dir: dir, ControlURL: controlURL, Hostname: "lab-" + name, Store: new(mem.Store), Ephemeral: true,
		Logf: logger.Discard, UserLogf: log.Printf}
	defer s.Close()
	st, err := s.Up(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, port := range []string{":8080", ":8081"} {
		ln, err := s.Listen("tcp", port)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				io.WriteString(c, name)
				c.Close()
			}
		}()
	}
	// UDP :9090 echoes "<name>:<payload>".
	pc, err := s.ListenPacket("udp", net.JoinHostPort(st.TailscaleIPs[0].String(), "9090"))
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte(name+":"), buf[:n]...), from)
		}
	}()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"tailnet": name, "ips": st.TailscaleIPs})
	select {}
}
