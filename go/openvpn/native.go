//go:build openvpn3

package openvpn

/*
#cgo CXXFLAGS: -std=c++17 -O2 -fvisibility=hidden -fvisibility-inlines-hidden -Wno-deprecated-declarations
#cgo CXXFLAGS: -DUSE_OPENSSL -DUSE_ASIO -DASIO_STANDALONE -DASIO_NO_DEPRECATED -DHAVE_LZ4
#cgo CXXFLAGS: -I${SRCDIR}/../../third_party/src/openvpn3 -I${SRCDIR}/../../third_party/src/asio/asio/include -I${SRCDIR}/../../third_party/src/lz4/lib
#cgo CFLAGS: -O2 -fvisibility=hidden
#cgo android,arm64 CXXFLAGS: -I${SRCDIR}/../../third_party/openssl/android_arm64/include
#cgo android,arm64 LDFLAGS: -L${SRCDIR}/../../third_party/openssl/android_arm64/lib
#cgo android,amd64 CXXFLAGS: -I${SRCDIR}/../../third_party/openssl/android_amd64/include
#cgo android,amd64 LDFLAGS: -L${SRCDIR}/../../third_party/openssl/android_amd64/lib
#cgo !android CXXFLAGS: -I${SRCDIR}/../../third_party/openssl/host/include
#cgo !android LDFLAGS: -L${SRCDIR}/../../third_party/openssl/host/lib
#cgo LDFLAGS: -lssl -lcrypto
#cgo android LDFLAGS: -static-libstdc++ -llog
#cgo darwin LDFLAGS: -framework CoreFoundation -framework SystemConfiguration -framework IOKit -framework CoreServices
#cgo linux,!android LDFLAGS: -lpthread

#include <stdlib.h>
#include <string.h>
#include "ovpn.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"runtime/cgo"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Available reports whether this build includes OpenVPN 3 Core.
func Available() bool { return true }

// Eval parses a profile without connecting.
func Eval(profile string) (Profile, error) {
	cp := C.CString(profile)
	defer C.free(unsafe.Pointer(cp))
	out := takeString(C.hv_ovpn_eval(cp))
	var p Profile
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		return p, err
	}
	return p, nil
}

// CheckKeyPassword reports whether password decrypts the profile's inline
// private key, so a wrong password is caught at import rather than at connect.
func CheckKeyPassword(profile, password string) (bool, error) {
	cp, cpw := C.CString(profile), C.CString(password)
	defer func() {
		C.free(unsafe.Pointer(cp))
		wipeCString(cpw, len(password))
		C.free(unsafe.Pointer(cpw))
	}()
	switch C.hv_ovpn_check_key_password(cp, cpw) {
	case 1:
		return true, nil
	case 0:
		return false, nil
	}
	return false, errors.New("openvpn: the profile has no inline private key")
}

// New prepares a session; Start connects.
func New(cfg Config) (*Client, error) {
	if cfg.ID == "" {
		return nil, errors.New("openvpn: missing id")
	}
	c := &Client{cfg: cfg, state: StateIdle, done: make(chan struct{})}
	h := cgo.NewHandle(c)
	n := &coreClient{h: h, p: C.hv_ovpn_new(C.uintptr_t(h))}
	cp, cu, cpw, ckp := C.CString(cfg.Profile), C.CString(cfg.Username), C.CString(cfg.Password), C.CString(cfg.KeyPassword)
	defer func() {
		C.free(unsafe.Pointer(cp))
		C.free(unsafe.Pointer(cu))
		wipeCString(cpw, len(cfg.Password))
		C.free(unsafe.Pointer(cpw))
		wipeCString(ckp, len(cfg.KeyPassword))
		C.free(unsafe.Pointer(ckp))
	}()
	if msg := C.hv_ovpn_configure(n.p, cp, cu, cpw, ckp); msg != nil {
		n.free()
		return nil, errors.New("openvpn: " + takeString(msg))
	}
	c.native = n
	return c, nil
}

func wipeCString(p *C.char, n int) {
	if n > 0 {
		C.memset(unsafe.Pointer(p), 0, C.size_t(n))
	}
}

func takeString(p *C.char) string {
	if p == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(p))
	return C.GoString(p)
}

type coreClient struct {
	h cgo.Handle
	p unsafe.Pointer
}

func (n *coreClient) connect() (status, error) {
	var st status
	err := json.Unmarshal([]byte(takeString(C.hv_ovpn_connect(n.p))), &st)
	return st, err
}

func (n *coreClient) stop()              { C.hv_ovpn_stop(n.p) }
func (n *coreClient) reconnect(secs int) { C.hv_ovpn_reconnect(n.p, C.int(secs)) }

func (n *coreClient) info() connectionInfo {
	var i connectionInfo
	json.Unmarshal([]byte(takeString(C.hv_ovpn_info(n.p))), &i)
	return i
}

func (n *coreClient) stats() (int64, int64) {
	var out [4]C.longlong
	C.hv_ovpn_stats(n.p, &out[0])
	return int64(out[0]), int64(out[1])
}

func (n *coreClient) counters() string { return takeString(C.hv_ovpn_counters(n.p)) }

func (n *coreClient) free() {
	C.hv_ovpn_free(n.p)
	n.h.Delete()
}

func client(h C.uintptr_t) *Client { return cgo.Handle(h).Value().(*Client) }

//export goOvpnProtect
func goOvpnProtect(h C.uintptr_t, fd C.int) C.int {
	if client(h).protect(int(fd)) {
		return 1
	}
	return 0
}

//export goOvpnEstablish
func goOvpnEstablish(h C.uintptr_t, config *C.char, fd C.int) C.int {
	var cfg TunConfig
	if err := json.Unmarshal([]byte(C.GoString(config)), &cfg); err != nil {
		unix.Close(int(fd))
		client(h).logf("bad tunnel config: %v", err)
		return 1
	}
	if client(h).onEstablish(int(fd), cfg) != nil {
		return 1 // newTunnel closed fd
	}
	return 0
}

//export goOvpnTeardown
func goOvpnTeardown(h C.uintptr_t, disconnect C.int) {
	client(h).onTeardown(disconnect != 0)
}

//export goOvpnEvent
func goOvpnEvent(h C.uintptr_t, name, info *C.char, isError, fatal C.int) {
	client(h).onEvent(C.GoString(name), C.GoString(info), isError != 0, fatal != 0)
}

//export goOvpnLog
func goOvpnLog(h C.uintptr_t, text *C.char) {
	client(h).logf("%s", C.GoString(text))
}
