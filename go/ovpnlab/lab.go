// Package ovpnlab runs a local OpenVPN server for tests, without Docker or
// root (macOS): an OpenVPN 2 server built by scripts/ovpnlab/build-server.sh
// whose utun device is replaced by utunshim with a Unix socket. Behind the
// server, a userspace network stack serves test endpoints:
//
//	10.8.0.1, fd00:8::1   the server's tunnel addresses (the VPN subnet)
//	10.9.0.1               a "remote network" reachable only via a pushed route
//	TCP 8080               banner "ovpnlab <dst>\n", then close
//	TCP 8081               echo
//	UDP 9090               echo
//	TCP 5201               hvbench's TCP protocol (bulk down/up, ping), for throughput
//
// The server pushes route 10.9.0.0/24, DNS 10.8.0.1 and domain lab.test. A
// fresh PKI (ECDSA CA, server and client certificates, tls-crypt key) is
// generated for every lab. Nothing here ships in the app.
package ovpnlab

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Options configures a lab.
type Options struct {
	Dir      string // work directory (keys, configs, sockets)
	OpenVPN  string // OpenVPN 2 binary
	Shim     string // utunshim.dylib
	Proto    string // "udp" (default) or "tcp"
	Port     int    // default 1194
	Listen   string // server bind address, default 0.0.0.0
	Remote   string // address written into the client profile, default 127.0.0.1
	Username string // non-empty: require username/password
	Password string
	// KeyPassword: encrypt the client's private key with it (PKCS#8, PBES2),
	// as many providers' profiles do.
	KeyPassword string
	Log         io.Writer // server output; nil discards
	Verb        int       // server log verbosity, default 3
	// Reuse keeps the keys and configs already in Dir (from an earlier run),
	// so a profile imported on a device keeps working across restarts.
	Reuse bool
}

// Lab is a running server.
type Lab struct {
	opts    Options
	Profile string // client .ovpn, inline
	cmd     *exec.Cmd
	sockDir string // short path: Unix socket paths are limited to 104 bytes
	conn    *net.UnixConn
	stack   *stack.Stack
	ep      *channel.Endpoint
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	exited  chan struct{}
}

// Binaries returns the lab server binaries built in repo's third_party/,
// or an error if they are missing.
func Binaries(repoRoot string) (openvpn, shim string, err error) {
	openvpn = filepath.Join(repoRoot, "third_party/ovpnlab/openvpn")
	shim = filepath.Join(repoRoot, "third_party/ovpnlab/utunshim.dylib")
	for _, p := range []string{openvpn, shim} {
		if _, err := os.Stat(p); err != nil {
			return "", "", fmt.Errorf("%s missing: run scripts/ovpnlab/build-server.sh", p)
		}
	}
	return openvpn, shim, nil
}

// Start generates keys and configs and starts the server. It returns once
// the server's tunnel is open (it is then ready for clients).
func Start(o Options) (_ *Lab, err error) {
	if o.Proto == "" {
		o.Proto = "udp"
	}
	if o.Port == 0 {
		o.Port = 1194
	}
	if o.Listen == "" {
		o.Listen = "0.0.0.0"
	}
	if o.Remote == "" {
		o.Remote = "127.0.0.1"
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.Verb == 0 {
		o.Verb = 3
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	l := &Lab{opts: o, exited: make(chan struct{})}
	old, rerr := os.ReadFile(filepath.Join(o.Dir, "client.ovpn"))
	_, serr := os.Stat(filepath.Join(o.Dir, "server.conf"))
	if o.Reuse && rerr == nil && serr == nil {
		l.Profile = string(old)
	} else {
		pki, err := newPKI(o.KeyPassword)
		if err != nil {
			return nil, err
		}
		server, profile := configs(o, pki)
		l.Profile = profile
		if err := os.WriteFile(filepath.Join(o.Dir, "server.conf"), []byte(server), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(o.Dir, "client.ovpn"), []byte(profile), 0o600); err != nil {
			return nil, err
		}
	}
	if o.Username != "" {
		// via-file: the server writes username and password to a temp file.
		script := fmt.Sprintf("#!/bin/sh\n[ \"$(sed -n 1p \"$1\")\" = %q ] && [ \"$(sed -n 2p \"$1\")\" = %q ]\n", o.Username, o.Password)
		if err := os.WriteFile(filepath.Join(o.Dir, "check-auth.sh"), []byte(script), 0o700); err != nil {
			return nil, err
		}
	}
	if err := l.startStack(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()

	cmd := exec.Command(o.OpenVPN, "--config", "server.conf")
	cmd.Dir = o.Dir
	cmd.Env = append(os.Environ(),
		"DYLD_INSERT_LIBRARIES="+o.Shim,
		"HV_UTUN_LOCAL="+filepath.Join(l.sockDir, "ovpn.sock"),
		"HV_UTUN_PEER="+filepath.Join(l.sockDir, "lab.sock"))
	ready := &readyWriter{w: o.Log, needle: []byte("Initialization Sequence Completed"), ch: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = ready, ready
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	l.cmd = cmd
	go func() { cmd.Wait(); close(l.exited) }()
	select {
	case <-ready.ch:
		return l, nil
	case <-l.exited:
		return nil, errors.New("openvpn server exited during startup (see its log)")
	case <-time.After(15 * time.Second):
		return nil, errors.New("openvpn server did not start within 15s")
	}
}

// Close stops the server and the stack.
func (l *Lab) Close() {
	if l.cmd != nil && l.cmd.Process != nil {
		l.cmd.Process.Signal(unix.SIGTERM)
		select {
		case <-l.exited:
		case <-time.After(5 * time.Second):
			l.cmd.Process.Kill()
			<-l.exited
		}
	}
	if l.cancel != nil {
		l.cancel()
	}
	if l.conn != nil {
		l.conn.Close()
	}
	l.wg.Wait()
	if l.sockDir != "" {
		os.RemoveAll(l.sockDir)
	}
	if l.stack != nil {
		l.ep.Close()
		l.stack.Close()
		l.stack.Wait()
	}
}

type readyWriter struct {
	mu     sync.Mutex
	w      io.Writer
	needle []byte
	buf    []byte
	ch     chan struct{}
	done   bool
}

func (r *readyWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.w.Write(p)
	if !r.done {
		r.buf = append(r.buf, p...)
		if bytes.Contains(r.buf, r.needle) {
			r.done = true
			r.buf = nil
			close(r.ch)
		} else if len(r.buf) > 4096 {
			r.buf = r.buf[len(r.buf)-len(r.needle):]
		}
	}
	return len(p), nil
}

// --- the network behind the server ---

func (l *Lab) startStack() error {
	dir, err := os.MkdirTemp("/tmp", "ovpnlab")
	if err != nil {
		return err
	}
	l.sockDir = dir
	sock := filepath.Join(dir, "lab.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return err
	}
	conn.SetReadBuffer(4 << 20)
	conn.SetWriteBuffer(4 << 20)
	l.conn = conn
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(512, 1500, "")
	if terr := s.CreateNIC(1, ep); terr != nil {
		return fmt.Errorf("create NIC: %v", terr)
	}
	l.stack, l.ep = s, ep
	for _, a := range []struct {
		addr tcpip.Address
		bits int
	}{
		{tcpip.AddrFrom4([4]byte{10, 8, 0, 1}), 24},
		{tcpip.AddrFrom4([4]byte{10, 9, 0, 1}), 24},
		{tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 8, 15: 1}), 64},
	} {
		proto := ipv4.ProtocolNumber
		if a.addr.Len() == 16 {
			proto = ipv6.ProtocolNumber
		}
		s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: proto,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: a.addr, PrefixLen: a.bits}}, stack.AddressProperties{})
	}
	v4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	v6, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFromBytes(make([]byte, 16)))
	s.SetRouteTable([]tcpip.Route{{Destination: v4, NIC: 1}, {Destination: v6, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	peer := &net.UnixAddr{Name: filepath.Join(dir, "ovpn.sock"), Net: "unixgram"}
	l.wg.Add(2)
	go func() { // server tunnel -> stack
		defer l.wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n <= 4 {
				continue
			}
			p := buf[4:n]
			proto := ipv4.ProtocolNumber
			if header.IPVersion(p) == header.IPv6Version {
				proto = ipv6.ProtocolNumber
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
			ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()
	go func() { // stack -> server tunnel
		defer l.wg.Done()
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			af := uint32(unix.AF_INET)
			if pkt.NetworkProtocolNumber == ipv6.ProtocolNumber {
				af = unix.AF_INET6
			}
			b := binary.BigEndian.AppendUint32(nil, af)
			for _, v := range pkt.AsSlices() {
				b = append(b, v...)
			}
			pkt.DecRef()
			conn.WriteToUnix(b, peer) // fails until the server opened its tunnel: dropped
		}
	}()
	return l.serve()
}

func (l *Lab) serve() error {
	// IPv6 TCP listeners are dual-stack: they serve IPv4 too.
	banner, err := gonet.ListenTCP(l.stack, tcpip.FullAddress{NIC: 1, Port: 8080}, ipv6.ProtocolNumber)
	if err != nil {
		return fmt.Errorf("listen 8080: %v", err)
	}
	echo, err := gonet.ListenTCP(l.stack, tcpip.FullAddress{NIC: 1, Port: 8081}, ipv6.ProtocolNumber)
	if err != nil {
		return fmt.Errorf("listen 8081: %v", err)
	}
	go accept(banner, func(c net.Conn) { fmt.Fprintf(c, "ovpnlab %s\n", c.LocalAddr()) })
	go accept(echo, func(c net.Conn) { io.Copy(c, c) })
	bench, err := gonet.ListenTCP(l.stack, tcpip.FullAddress{NIC: 1, Port: 5201}, ipv6.ProtocolNumber)
	if err != nil {
		return fmt.Errorf("listen 5201: %v", err)
	}
	go accept(bench, serveBench)
	// UDP replies must come from the address the client sent to: one socket per address.
	for _, a := range []tcpip.Address{
		tcpip.AddrFrom4([4]byte{10, 8, 0, 1}),
		tcpip.AddrFrom4([4]byte{10, 9, 0, 1}),
		tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 8, 15: 1}),
	} {
		proto := ipv4.ProtocolNumber
		if a.Len() == 16 {
			proto = ipv6.ProtocolNumber
		}
		uecho, err := gonet.DialUDP(l.stack, &tcpip.FullAddress{NIC: 1, Addr: a, Port: 9090}, nil, proto)
		if err != nil {
			return fmt.Errorf("listen %s:9090: %v", a, err)
		}
		go func() {
			buf := make([]byte, 65536)
			for {
				n, from, err := uecho.ReadFrom(buf)
				if err != nil {
					return
				}
				uecho.WriteTo(buf[:n], from)
			}
		}()
	}
	return nil
}

// serveBench speaks cmd/hvbench's TCP protocol: 'D' + 8-byte length sends
// that many bytes, 'U' + length reads them and answers with the count, 'P'
// echoes one byte.
func serveBench(c net.Conn) {
	var cmd [1]byte
	if _, err := io.ReadFull(c, cmd[:]); err != nil {
		return
	}
	switch cmd[0] {
	case 'P':
		c.Write(cmd[:])
	case 'D', 'U':
		var n [8]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		total := int64(binary.BigEndian.Uint64(n[:]))
		if cmd[0] == 'D' {
			io.CopyN(c, zeros{}, total)
			return
		}
		got, _ := io.CopyN(io.Discard, c, total)
		binary.BigEndian.PutUint64(n[:], uint64(got))
		c.Write(n[:])
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func accept(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			handle(c)
		}()
	}
}

// --- keys and configs ---

type pki struct {
	ca, serverCert, serverKey, clientCert, clientKey, tlsCrypt string
}

func newPKI(clientKeyPassword string) (*pki, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ovpnlab CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leaf := func(serial int64, cn string, usage x509.ExtKeyUsage) (string, string, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", "", err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return "", "", err
		}
		kder, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", "", err
		}
		return pemString("CERTIFICATE", der), pemString("PRIVATE KEY", kder), nil
	}
	p := &pki{ca: pemString("CERTIFICATE", caDER)}
	if p.serverCert, p.serverKey, err = leaf(2, "server", x509.ExtKeyUsageServerAuth); err != nil {
		return nil, err
	}
	if p.clientCert, p.clientKey, err = leaf(3, "client", x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	if clientKeyPassword != "" {
		block, _ := pem.Decode([]byte(p.clientKey))
		enc, err := encryptPKCS8(block.Bytes, clientKeyPassword)
		if err != nil {
			return nil, err
		}
		p.clientKey = pemString("ENCRYPTED PRIVATE KEY", enc)
	}
	static := make([]byte, 256)
	rand.Read(static)
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(static); i += 16 {
		b.WriteString(hex.EncodeToString(static[i:i+16]) + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	p.tlsCrypt = b.String()
	return p, nil
}

// encryptPKCS8 wraps a PKCS#8 key as EncryptedPrivateKeyInfo with PBES2
// (PBKDF2-HMAC-SHA256, AES-256-CBC), the format `openssl pkcs8 -topk8 -v2`
// writes.
func encryptPKCS8(der []byte, password string) ([]byte, error) {
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	rand.Read(salt)
	rand.Read(iv)
	const iterations = 10000
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(der)%aes.BlockSize
	data := append(append([]byte(nil), der...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)

	type algorithm struct {
		OID    asn1.ObjectIdentifier
		Params asn1.RawValue `asn1:"optional"`
	}
	raw := func(v any) asn1.RawValue {
		b, _ := asn1.Marshal(v)
		return asn1.RawValue{FullBytes: b}
	}
	kdf := raw(struct {
		Salt       []byte
		Iterations int
		KeyLength  int
		PRF        algorithm
	}{salt, iterations, 32, algorithm{asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}, asn1.NullRawValue}})
	params := raw(struct{ KDF, Scheme algorithm }{
		algorithm{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}, kdf},
		algorithm{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, raw(iv)},
	})
	return asn1.Marshal(struct {
		Algorithm algorithm
		Data      []byte
	}{algorithm{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, params}, data})
}

func pemString(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

func inline(tag, body string) string { return "<" + tag + ">\n" + body + "</" + tag + ">\n" }

func configs(o Options, p *pki) (server, client string) {
	serverProto, clientProto := "udp", "udp"
	if o.Proto == "tcp" {
		serverProto, clientProto = "tcp-server", "tcp-client"
	}
	var s strings.Builder
	fmt.Fprintf(&s, `dev tun
dev-node utun99
ifconfig-noexec
route-noexec
topology subnet
server 10.8.0.0 255.255.255.0
server-ipv6 fd00:8::/64
proto %s
local %s
port %d
dh none
keepalive 10 60
data-ciphers AES-256-GCM:CHACHA20-POLY1305
push "route 10.9.0.0 255.255.255.0"
push "dhcp-option DNS 10.8.0.1"
push "dhcp-option DOMAIN lab.test"
verb %d
`, serverProto, o.Listen, o.Port, o.Verb)
	if o.Username != "" {
		s.WriteString("script-security 2\nauth-user-pass-verify check-auth.sh via-file\n")
	}
	s.WriteString(inline("ca", p.ca) + inline("cert", p.serverCert) + inline("key", p.serverKey) + inline("tls-crypt", p.tlsCrypt))

	var c strings.Builder
	fmt.Fprintf(&c, `client
dev tun
proto %s
remote %s %d
nobind
remote-cert-tls server
verb 3
`, clientProto, o.Remote, o.Port)
	if o.Username != "" {
		c.WriteString("auth-user-pass\n")
	}
	c.WriteString(inline("ca", p.ca) + inline("cert", p.clientCert) + inline("key", p.clientKey) + inline("tls-crypt", p.tlsCrypt))
	return s.String(), c.String()
}
