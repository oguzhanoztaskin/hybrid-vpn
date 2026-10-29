// The NDK sysroot provides jni.h for Android builds. On the host, build with
// -tags jnihost and CGO_CFLAGS pointing at a JDK's include directories.

//go:build android || jnihost

// Command jni builds libhybridvpn_go.so, the Go side of the Kotlin bridge
// (com.oguzhanstech.hybridvpn.gobridge.GoBridge).
//
// Build with -buildmode=c-shared. Packets never cross JNI. Calls into Go:
// control (start/stop/stats). Calls into Kotlin ("upcalls"): socket
// protection once per socket, DNS once per query, and an engine-stopped event.
package main

/*
#include <jni.h>
#include <stdlib.h>
#include <string.h>

static JavaVM *g_vm;
static jclass g_bridge;
static jmethodID g_protect, g_dns, g_stopped, g_owner, g_ifaces;

static jstring newString(JNIEnv *env, const char *s) {
	return (*env)->NewStringUTF(env, s);
}

static const char *getChars(JNIEnv *env, jstring s) {
	return (*env)->GetStringUTFChars(env, s, NULL);
}

static void releaseChars(JNIEnv *env, jstring s, const char *chars) {
	(*env)->ReleaseStringUTFChars(env, s, chars);
}

// bridgeInit must run on a Java thread: it caches the class (FindClass from a
// native thread would use the wrong class loader) and the upcall method IDs.
static int bridgeInit(JNIEnv *env, jclass clazz) {
	if (g_vm == NULL && (*env)->GetJavaVM(env, &g_vm) != JNI_OK) return 0;
	if (g_bridge == NULL) g_bridge = (jclass)(*env)->NewGlobalRef(env, clazz);
	g_protect = (*env)->GetStaticMethodID(env, clazz, "protect", "(I)Z");
	g_dns = (*env)->GetStaticMethodID(env, clazz, "dnsQuery", "([B[BI[BIZ)[B");
	g_stopped = (*env)->GetStaticMethodID(env, clazz, "onEngineStopped", "(Ljava/lang/String;)V");
	g_owner = (*env)->GetStaticMethodID(env, clazz, "ownerUid", "(I[BI[BI)I");
	g_ifaces = (*env)->GetStaticMethodID(env, clazz, "interfaces", "()Ljava/lang/String;");
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		return 0;
	}
	return g_protect != NULL && g_dns != NULL && g_stopped != NULL && g_owner != NULL && g_ifaces != NULL;
}

// attachEnv returns a JNIEnv for the current OS thread, attaching Go-created
// threads as daemons (they never return to Java, so they must not block VM exit).
static JNIEnv *attachEnv(void) {
	JNIEnv *env = NULL;
	if (g_vm == NULL) return NULL;
	if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) return env;
#ifdef __ANDROID__
	if ((*g_vm)->AttachCurrentThreadAsDaemon(g_vm, &env, NULL) != JNI_OK) return NULL;
#else
	if ((*g_vm)->AttachCurrentThreadAsDaemon(g_vm, (void **)&env, NULL) != JNI_OK) return NULL;
#endif
	return env;
}

static int callProtect(int fd) {
	JNIEnv *env = attachEnv();
	if (env == NULL) return 0;
	jboolean ok = (*env)->CallStaticBooleanMethod(env, g_bridge, g_protect, (jint)fd);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		return 0;
	}
	return ok == JNI_TRUE;
}

static jbyteArray bytes(JNIEnv *env, const void *p, int n) {
	jbyteArray a = (*env)->NewByteArray(env, n);
	if (a != NULL) (*env)->SetByteArrayRegion(env, a, 0, n, (const jbyte *)p);
	return a;
}

// callDNS returns the answer length written to out, -1 for no answer, -2 if
// the answer does not fit. Local references live in a frame: attached daemon
// threads never return to Java, so leaked references would accumulate.
static int callDNS(const void *q, int qlen, const void *src, int srclen, int sport,
                   const void *dst, int dstlen, int dport, int tcp, void *out, int outcap) {
	JNIEnv *env = attachEnv();
	if (env == NULL) return -1;
	if ((*env)->PushLocalFrame(env, 8) != 0) {
		(*env)->ExceptionClear(env);
		return -1;
	}
	int ret = -1;
	jbyteArray jq = bytes(env, q, qlen), js = bytes(env, src, srclen), jd = bytes(env, dst, dstlen);
	if (jq != NULL && js != NULL && jd != NULL) {
		jbyteArray r = (jbyteArray)(*env)->CallStaticObjectMethod(env, g_bridge, g_dns, jq, js, (jint)sport, jd, (jint)dport,
			tcp ? JNI_TRUE : JNI_FALSE);
		if (!(*env)->ExceptionCheck(env) && r != NULL) {
			jsize n = (*env)->GetArrayLength(env, r);
			if (n <= outcap) {
				(*env)->GetByteArrayRegion(env, r, 0, n, (jbyte *)out);
				ret = n;
			} else {
				ret = -2;
			}
		}
	}
	if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	(*env)->PopLocalFrame(env, NULL);
	return ret;
}

// callOwner returns the Android UID owning a flow, or -1 if unknown.
static int callOwner(int proto, const void *src, int srclen, int sport, const void *dst, int dstlen, int dport) {
	JNIEnv *env = attachEnv();
	if (env == NULL) return -1;
	if ((*env)->PushLocalFrame(env, 4) != 0) {
		(*env)->ExceptionClear(env);
		return -1;
	}
	int uid = -1;
	jbyteArray js = bytes(env, src, srclen), jd = bytes(env, dst, dstlen);
	if (js != NULL && jd != NULL) {
		uid = (*env)->CallStaticIntMethod(env, g_bridge, g_owner, (jint)proto, js, (jint)sport, jd, (jint)dport);
		if ((*env)->ExceptionCheck(env)) {
			(*env)->ExceptionClear(env);
			uid = -1;
		}
	}
	(*env)->PopLocalFrame(env, NULL);
	return uid;
}

// callInterfaces returns a malloc'd UTF-8 JSON string (caller frees), or NULL.
static char *callInterfaces(void) {
	JNIEnv *env = attachEnv();
	if (env == NULL) return NULL;
	if ((*env)->PushLocalFrame(env, 2) != 0) {
		(*env)->ExceptionClear(env);
		return NULL;
	}
	char *out = NULL;
	jstring s = (jstring)(*env)->CallStaticObjectMethod(env, g_bridge, g_ifaces);
	if (!(*env)->ExceptionCheck(env) && s != NULL) {
		const char *chars = (*env)->GetStringUTFChars(env, s, NULL);
		if (chars != NULL) {
			out = strdup(chars);
			(*env)->ReleaseStringUTFChars(env, s, chars);
		}
	}
	if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	(*env)->PopLocalFrame(env, NULL);
	return out;
}

static void callStopped(const char *reason) {
	JNIEnv *env = attachEnv();
	if (env == NULL) return;
	if ((*env)->PushLocalFrame(env, 2) != 0) {
		(*env)->ExceptionClear(env);
		return;
	}
	jstring s = reason ? (*env)->NewStringUTF(env, reason) : NULL;
	(*env)->CallStaticVoidMethod(env, g_bridge, g_stopped, s);
	if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	(*env)->PopLocalFrame(env, NULL);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"hybridvpn/netcore/engine"
	"hybridvpn/netcore/httpproxy"
	"hybridvpn/netcore/openvpn"
	"hybridvpn/netcore/socks"
	"hybridvpn/netcore/tailnet"
	"tailscale.com/net/netmon"
)

func goString(env *C.JNIEnv, s C.jstring) string {
	if s == 0 {
		return ""
	}
	chars := C.getChars(env, s)
	if chars == nil {
		return ""
	}
	defer C.releaseChars(env, s, chars)
	return C.GoString(chars)
}

func javaString(env *C.JNIEnv, s string) C.jstring {
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	return C.newString(env, cs)
}

// jniHost implements engine.Host by calling back into GoBridge.
type jniHost struct{}

func (jniHost) Protect(fd int) bool { return C.callProtect(C.int(fd)) != 0 }

func (jniHost) OwnerUID(f engine.Flow) int {
	src, dst := f.Src.Addr().Unmap().AsSlice(), f.Dst.Addr().Unmap().AsSlice()
	return int(C.callOwner(C.int(f.Protocol),
		unsafe.Pointer(&src[0]), C.int(len(src)), C.int(f.Src.Port()),
		unsafe.Pointer(&dst[0]), C.int(len(dst)), C.int(f.Dst.Port())))
}

var answerPool = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

func (jniHost) DNS(q []byte, f engine.Flow) []byte {
	if len(q) == 0 {
		return nil
	}
	src, dst := f.Src.Addr().Unmap().AsSlice(), f.Dst.Addr().Unmap().AsSlice()
	bp := answerPool.Get().(*[]byte)
	defer answerPool.Put(bp)
	out := *bp
	tcp := 0
	if f.Protocol == engine.TCP {
		tcp = 1
	}
	n := C.callDNS(unsafe.Pointer(&q[0]), C.int(len(q)),
		unsafe.Pointer(&src[0]), C.int(len(src)), C.int(f.Src.Port()),
		unsafe.Pointer(&dst[0]), C.int(len(dst)), C.int(f.Dst.Port()),
		C.int(tcp), unsafe.Pointer(&out[0]), C.int(len(out)))
	if n < 0 {
		return nil
	}
	return append([]byte(nil), out[:n]...)
}

type engineConfig struct {
	AllowICMP   bool   `json:"allow_icmp"`
	AllowICMPv6 bool   `json:"allow_icmpv6"`
	MTU         uint32 `json:"mtu"`
	// DisableRACK: Settings → Performance, "TCP loss detection" off.
	DisableRACK bool `json:"disable_rack"`
	// DisablePacketForwarding: Settings → Performance, "OpenVPN packet forwarding" off.
	DisablePacketForwarding bool            `json:"disable_packet_forwarding"`
	Tunnel                  []string        `json:"tunnel"`
	Resolvers               []string        `json:"resolvers"`
	Policy                  json.RawMessage `json:"policy"` // installed before the first packet
	// CrashLog receives Go's fatal error and panic output (stderr is discarded on Android).
	CrashLog string `json:"crash_log"`
	// LogsDir and TempDir are app-private directories. An Android app process
	// has no $HOME, cache dir or writable temp dir, which Tailscale's local
	// log state needs (uploads stay disabled).
	LogsDir string `json:"logs_dir"`
	TempDir string `json:"temp_dir"`
	// Tailnets become transports "tailnet:<id>". State lives in Dir (app-private).
	Tailnets []struct {
		ID         string `json:"id"`
		Dir        string `json:"dir"`
		ControlURL string `json:"control_url"`
		Hostname   string `json:"hostname"`
	} `json:"tailnets"`
	// OpenVPN profiles become transports "openvpn:<id>".
	OpenVPN []struct {
		ID          string `json:"id"`
		Profile     string `json:"profile"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		KeyPassword string `json:"key_password"`
	} `json:"openvpn"`
	// HTTP proxies become TCP-only transports "http:<id>".
	HTTP []struct {
		ID       string `json:"id"`
		Server   string `json:"server"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"http"`
	// SOCKS5 proxies become transports "socks5:<id>".
	SOCKS5 []struct {
		ID       string `json:"id"`
		Server   string `json:"server"` // host:port
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"socks5"`
}

// jniInterfaces lists the physical networks' interfaces as Kotlin sees them
// (Android denies net.Interfaces to apps, and the routing-based fallback
// would see our own tunnel). JSON: [{"name","index","mtu","addrs":["ip/len"]}].
func jniInterfaces() ([]netmon.Interface, error) {
	cs := C.callInterfaces()
	if cs == nil {
		return nil, errors.New("interfaces upcall failed")
	}
	raw := C.GoString(cs)
	C.free(unsafe.Pointer(cs))
	var list []struct {
		Name  string   `json:"name"`
		Index int      `json:"index"`
		MTU   int      `json:"mtu"`
		Addrs []string `json:"addrs"`
	}
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, err
	}
	var out []netmon.Interface
	for _, it := range list {
		ni := netmon.Interface{Interface: &net.Interface{Index: it.Index, MTU: it.MTU, Name: it.Name,
			Flags: net.FlagUp | net.FlagRunning | net.FlagMulticast}}
		for _, a := range it.Addrs {
			if p, err := netip.ParsePrefix(a); err == nil {
				ni.AltAddrs = append(ni.AltAddrs, &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
			}
		}
		out = append(out, ni)
	}
	return out, nil
}

var (
	mu          sync.Mutex
	current     *engine.Engine
	tailnets    *tailnet.Manager
	vpns        []*openvpn.Client
	proxies     []*socks.Proxy
	httpProxies []*httpproxy.Proxy
)

//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_version
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_version(env *C.JNIEnv, clazz C.jclass) C.jstring {
	return javaString(env, fmt.Sprintf("netcore %s/%s %s", runtime.GOOS, runtime.GOARCH, runtime.Version()))
}

//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_echo
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_echo(env *C.JNIEnv, clazz C.jclass, s C.jstring) C.jstring {
	return javaString(env, "go:"+goString(env, s))
}

//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_nativeInit
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_nativeInit(env *C.JNIEnv, clazz C.jclass) C.jboolean {
	if C.bridgeInit(env, clazz) == 0 {
		return C.JNI_FALSE
	}
	return C.JNI_TRUE
}

// startEngine takes ownership of fd in every case, including errors. It
// returns null on success or an error message.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_startEngine
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_startEngine(env *C.JNIEnv, clazz C.jclass, fd C.jint, config C.jstring) C.jstring {
	err := startEngine(int(fd), goString(env, config))
	if err != nil {
		return javaString(env, err.Error())
	}
	return 0
}

func startEngine(fd int, configJSON string) (err error) {
	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()
	var cfg engineConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.CrashLog != "" {
		if f, err := os.OpenFile(cfg.CrashLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			debug.SetCrashOutput(f, debug.CrashOptions{})
			f.Close() // SetCrashOutput keeps its own duplicate
		}
	}
	var tunnel []netip.Prefix
	for _, s := range cfg.Tunnel {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("config tunnel: %w", err)
		}
		tunnel = append(tunnel, p.Masked())
	}
	var resolvers []netip.Addr
	for _, s := range cfg.Resolvers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("config resolver: %w", err)
		}
		resolvers = append(resolvers, a)
	}
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		return fmt.Errorf("engine already running")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("set non-blocking: %w", err)
	}
	direct := engine.NewDirect(jniHost{}.Protect)
	transports := []engine.Transport{direct}
	var m *tailnet.Manager
	if len(cfg.Tailnets) > 0 {
		if cfg.LogsDir == "" || cfg.TempDir == "" {
			return errors.New("tailnets need logs_dir and temp_dir")
		}
		if err := os.MkdirAll(cfg.LogsDir, 0o700); err != nil {
			return err
		}
		os.Setenv("TS_LOGS_DIR", cfg.LogsDir)
		os.Setenv("TMPDIR", cfg.TempDir)
		setupTailscale() // process-wide: socket protection, interface getter, Android fixes
		m = tailnet.NewManager()
		for _, tc := range cfg.Tailnets {
			inst, err := m.Add(tailnet.Config{ID: tc.ID, StateDir: tc.Dir, ControlURL: tc.ControlURL, Hostname: tc.Hostname})
			if err != nil {
				m.Close()
				return err
			}
			transports = append(transports, inst.Transport())
		}
	}
	var ovpns []*openvpn.Client
	for _, oc := range cfg.OpenVPN {
		c, err := openvpn.New(openvpn.Config{ID: oc.ID, Profile: oc.Profile, Username: oc.Username, Password: oc.Password,
			KeyPassword: oc.KeyPassword,
			Protect:     jniHost{}.Protect})
		if err != nil {
			// The profile's routes fail closed; the rest of the VPN keeps working.
			c = openvpn.NewFailed(oc.ID, err)
		}
		ovpns = append(ovpns, c)
		transports = append(transports, c.Transport())
	}
	var httpClients []*httpproxy.Proxy
	for _, hc := range cfg.HTTP {
		p, err := httpproxy.New(httpproxy.Config{ID: hc.ID, Server: hc.Server, Username: hc.Username, Password: hc.Password, Dial: direct.DialAddress})
		if err != nil {
			p = httpproxy.NewFailed(hc.ID, hc.Server, err)
		}
		httpClients = append(httpClients, p)
		transports = append(transports, p.Transport())
	}
	var socksProxies []*socks.Proxy
	for _, sc := range cfg.SOCKS5 {
		p, err := socks.New(socks.Config{ID: sc.ID, Server: sc.Server, Username: sc.Username, Password: sc.Password,
			Dial: direct.DialAddress})
		if err != nil {
			// The proxy's routes fail closed; the rest of the VPN keeps working.
			p = socks.NewFailed(sc.ID, sc.Server, err)
		}
		socksProxies = append(socksProxies, p)
		transports = append(transports, p.Transport())
	}
	stopVPNs := func() {
		for _, c := range ovpns {
			c.Stop()
		}
	}
	e, err := engine.Start(engine.Config{
		TUN:                     os.NewFile(uintptr(fd), "tun"),
		MTU:                     cfg.MTU,
		Host:                    jniHost{},
		Tunnel:                  tunnel,
		Resolvers:               resolvers,
		Policy:                  cfg.Policy,
		Transports:              transports,
		DisableRACK:             cfg.DisableRACK,
		AllowICMP:               cfg.AllowICMP,
		AllowICMPv6:             cfg.AllowICMPv6,
		DisablePacketForwarding: cfg.DisablePacketForwarding,
	})
	if err != nil {
		fd = -1 // engine.Start closed it
		if m != nil {
			m.Close()
		}
		stopVPNs()
		return err
	}
	current, tailnets, vpns, proxies, httpProxies = e, m, ovpns, socksProxies, httpClients
	checkHTTPProxies(httpClients)
	checkProxies(socksProxies)
	for _, c := range ovpns {
		c.Start() // connects in the background; until connected its transport refuses flows
	}
	if m != nil {
		// Connect in the background: a tailnet may wait for interactive login.
		// Until it is Running its transport refuses flows (fail closed).
		for _, inst := range m.All() {
			go inst.Start()
		}
	}
	go func() {
		<-e.Done()
		mu.Lock()
		stoppedByHost := current != e
		if !stoppedByHost {
			current = nil
		}
		mu.Unlock()
		if !stoppedByHost {
			reason := e.Stats().Error
			if reason == "" {
				reason = "engine stopped"
			}
			cs := C.CString(reason)
			C.callStopped(cs)
			C.free(unsafe.Pointer(cs))
		}
	}()
	return nil
}

// setPolicy replaces the per-flow policy. Returns null on success or an
// error message (the previous policy stays in force).
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_setPolicy
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_setPolicy(env *C.JNIEnv, clazz C.jclass, policy C.jstring) C.jstring {
	mu.Lock()
	e := current
	mu.Unlock()
	if e == nil {
		return javaString(env, "engine not running")
	}
	if err := e.SetPolicy([]byte(goString(env, policy))); err != nil {
		return javaString(env, err.Error())
	}
	return 0
}

//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_stopEngine
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_stopEngine(env *C.JNIEnv, clazz C.jclass) {
	mu.Lock()
	e, m, v := current, tailnets, vpns
	current, tailnets, vpns, proxies, httpProxies = nil, nil, nil, nil, nil
	mu.Unlock()
	if e != nil {
		e.Stop()
	}
	if m != nil {
		m.Close()
	}
	for _, c := range v {
		c.Stop()
	}
}

// resolveTailnetName answers a MagicDNS name from the one tailnet owning its
// suffix (JSON tailnet.NameResult). Called by the Kotlin DNS firewall.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_resolveTailnetName
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_resolveTailnetName(env *C.JNIEnv, clazz C.jclass, name C.jstring) C.jstring {
	mu.Lock()
	m := tailnets
	mu.Unlock()
	r := tailnet.NameResult{Status: tailnet.NameNotTailnet}
	if m != nil {
		r = m.Resolve(goString(env, name))
	}
	b, _ := json.Marshal(r)
	return javaString(env, string(b))
}

// tailnetPeers returns {"<tailnet id>": [tailnet.PeerInfo...]} for every
// running tailnet, for the Devices screen.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_tailnetPeers
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_tailnetPeers(env *C.JNIEnv, clazz C.jclass) C.jstring {
	mu.Lock()
	m := tailnets
	mu.Unlock()
	out := map[string][]tailnet.PeerInfo{}
	if m != nil {
		// Each tailnet gets its own deadline, so a slow one can't hide the
		// others. A tailnet not read yet is listed with no machines rather
		// than left out, which would read as "not running".
		var wg sync.WaitGroup
		var outMu sync.Mutex
		for _, inst := range m.All() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				peers, _ := inst.Peers(ctx)
				if peers == nil {
					peers = []tailnet.PeerInfo{}
				}
				outMu.Lock()
				out[inst.ID()] = peers
				outMu.Unlock()
			}()
		}
		wg.Wait()
	}
	b, _ := json.Marshal(out)
	return javaString(env, string(b))
}

// tailnetStatus returns a JSON array of tailnet.Summary for the UI.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_tailnetStatus
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_tailnetStatus(env *C.JNIEnv, clazz C.jclass) C.jstring {
	mu.Lock()
	m := tailnets
	mu.Unlock()
	out := []tailnet.Summary{}
	if m != nil {
		// Each tailnet gets its own deadline, so a slow one can't make the others time out.
		all := m.All()
		sums := make([]tailnet.Summary, len(all))
		var wg sync.WaitGroup
		for i, inst := range all {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				sums[i] = inst.Summary(ctx)
			}()
		}
		wg.Wait()
		out = append(out, sums...)
	}
	b, _ := json.Marshal(out)
	return javaString(env, string(b))
}

// notifyNetworkChanged tells every tailnet that the physical network changed, so it
// rebinds its sockets and rediscovers endpoints now rather than on its slow
// (10 minute) Android poll. OpenVPN sessions reconnect and proxies are checked again.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_notifyNetworkChanged
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_notifyNetworkChanged(env *C.JNIEnv, clazz C.jclass) {
	mu.Lock()
	m, v, ps, hs := tailnets, vpns, proxies, httpProxies
	mu.Unlock()
	checkProxies(ps)
	checkHTTPProxies(hs)
	// The VPN transport sockets were bound to the old network: reconnect now
	// instead of waiting for the keepalive timeout.
	for _, c := range v {
		c.Reconnect()
	}
	if m == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, inst := range m.All() {
			inst.Rebind(ctx)
		}
	}()
}

// openvpnLinked reports whether this build includes OpenVPN 3 Core.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnLinked
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnLinked(env *C.JNIEnv, clazz C.jclass) C.jboolean {
	if openvpn.Available() {
		return C.JNI_TRUE
	}
	return C.JNI_FALSE
}

// openvpnParse parses a profile without connecting (JSON openvpn.Profile).
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnParse
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnParse(env *C.JNIEnv, clazz C.jclass, profile C.jstring) C.jstring {
	p, err := openvpn.Eval(goString(env, profile))
	if err != nil {
		p = openvpn.Profile{Error: true, Message: err.Error()}
	}
	b, _ := json.Marshal(p)
	return javaString(env, string(b))
}

// openvpnCheckKey reports whether password decrypts the profile's private
// key: 1 yes, 0 no, -1 no inline key or OpenVPN unavailable.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnCheckKey
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnCheckKey(env *C.JNIEnv, clazz C.jclass, profile, password C.jstring) C.jint {
	ok, err := openvpn.CheckKeyPassword(goString(env, profile), goString(env, password))
	switch {
	case err != nil:
		return -1
	case ok:
		return 1
	}
	return 0
}

// openvpnStatus returns a JSON array of openvpn.Summary for the UI.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnStatus
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnStatus(env *C.JNIEnv, clazz C.jclass) C.jstring {
	mu.Lock()
	v := vpns
	mu.Unlock()
	out := []openvpn.Summary{}
	for _, c := range v {
		out = append(out, c.Summary())
	}
	b, _ := json.Marshal(out)
	return javaString(env, string(b))
}

// checkProxies connects to each SOCKS5 proxy in the background, so the UI shows
// whether it is reachable before any flow uses it.
func checkProxies(ps []*socks.Proxy) {
	for _, p := range ps {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			p.Check(ctx)
		}()
	}
}

func checkHTTPProxies(ps []*httpproxy.Proxy) {
	for _, p := range ps {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			p.Check(ctx)
		}()
	}
}

// socksStatus returns HTTP then SOCKS5 summaries, retaining the JNI entrypoint.
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_socksStatus
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_socksStatus(env *C.JNIEnv, clazz C.jclass) C.jstring {
	mu.Lock()
	ps, hs := proxies, httpProxies
	mu.Unlock()
	out := []any{}
	for _, p := range hs {
		out = append(out, p.Summary())
	}
	for _, p := range ps {
		out = append(out, p.Summary())
	}
	b, _ := json.Marshal(out)
	return javaString(env, string(b))
}

// openvpnLog returns a profile's recent log lines (JSON array of strings).
//
//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnLog
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_openvpnLog(env *C.JNIEnv, clazz C.jclass, id C.jstring) C.jstring {
	mu.Lock()
	v := vpns
	mu.Unlock()
	want := goString(env, id)
	lines := []string{}
	for _, c := range v {
		if c.ID() == want {
			lines = c.Logs()
		}
	}
	b, _ := json.Marshal(lines)
	return javaString(env, string(b))
}

//export Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_engineStats
func Java_com_oguzhanstech_hybridvpn_gobridge_GoBridge_engineStats(env *C.JNIEnv, clazz C.jclass) C.jstring {
	mu.Lock()
	e := current
	mu.Unlock()
	var st engine.Stats
	if e != nil {
		st = e.Stats()
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b, _ := json.Marshal(struct {
		engine.Stats
		GoHeapBytes uint64 `json:"goHeapBytes"`
		GoSysBytes  uint64 `json:"goSysBytes"`
		Goroutines  int    `json:"goroutines"`
	}{st, ms.HeapAlloc, ms.Sys, runtime.NumGoroutine()})
	return javaString(env, string(b))
}

func main() {}
