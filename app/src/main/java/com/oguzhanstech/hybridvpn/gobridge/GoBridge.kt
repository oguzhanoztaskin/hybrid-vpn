package com.oguzhanstech.hybridvpn.gobridge

import org.json.JSONObject

/**
 * Kotlin side of the Go network engine (ADR 0003). The native library is optional: builds without
 * an Android NDK don't contain it, and everything else keeps working.
 *
 * Packets never cross JNI; Go owns a duplicate of the TUN fd. Go calls back ("upcalls") to
 * protect sockets, to answer DNS through the Kotlin DNS firewall, and to report an unexpected stop.
 */
object GoBridge {
    /** Callbacks from the engine. Invoked on Go-owned threads; implementations must be thread-safe. */
    interface Host {
        fun protect(fd: Int): Boolean
        fun dnsQuery(query: ByteArray, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int, tcp: Boolean): ByteArray?
        /** UID owning a flow ([protocol] is 6 or 17), or -1 if unknown. Called once per new flow when the policy matches on apps. */
        fun ownerUid(protocol: Int, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int): Int
        fun onEngineStopped(reason: String)
        /** JSON list of the physical networks' interfaces (see go/jni jniInterfaces). */
        fun interfaces(): String
    }

    /** Null when the library loaded, otherwise why it didn't. */
    val loadError: String? = try {
        System.loadLibrary("hybridvpn_go")
        null
    } catch (e: UnsatisfiedLinkError) {
        e.message ?: "library not bundled"
    }

    val available: Boolean get() = loadError == null

    @Volatile var host: Host? = null

    private val initialized: Boolean by lazy { available && nativeInit() }

    /**
     * Starts the engine on [tunFd]. Ownership of the fd passes to Go in every case, including
     * failure. Returns null on success or an error message.
     */
    fun start(tunFd: Int, configJson: String): String? {
        if (!initialized) {
            android.os.ParcelFileDescriptor.adoptFd(tunFd).close()
            return "Go engine not available: ${loadError ?: "JNI initialisation failed"}"
        }
        return startEngine(tunFd, configJson)
    }

    /** Stops the engine and closes its fd. Returns within a few seconds at most; call off the main thread. */
    fun stop() {
        if (initialized) stopEngine()
    }

    /** Replaces the engine's per-flow policy. Returns null on success; on error the old policy stays. */
    fun updatePolicy(json: String): String? = if (initialized) setPolicy(json) else "Go engine not available"

    /** Per-tailnet status (id, state, auth_url, ips, peers, error); empty when none run. */
    fun tailnets(): org.json.JSONArray = if (initialized) runCatching { org.json.JSONArray(tailnetStatus()) }.getOrDefault(org.json.JSONArray()) else org.json.JSONArray()

    /** Machines per running tailnet: {"<id>": [peer...]} (see go/tailnet PeerInfo). */
    fun tailnetMachines(): JSONObject = if (initialized) runCatching { JSONObject(tailnetPeers()) }.getOrDefault(JSONObject()) else JSONObject()

    /** MagicDNS lookup across running tailnets (JSON tailnet.NameResult), or null if unavailable. */
    fun resolveTailnet(name: String): JSONObject? = if (initialized) runCatching { JSONObject(resolveTailnetName(name)) }.getOrNull() else null

    /** Whether this build links OpenVPN 3 Core. */
    val openvpnAvailable: Boolean get() = initialized && runCatching { openvpnLinked() }.getOrDefault(false)

    /** Parses an OpenVPN profile without connecting (go/openvpn Profile JSON). */
    fun openvpnEval(profile: String): JSONObject =
        if (initialized) runCatching { JSONObject(openvpnParse(profile)) }.getOrElse { JSONObject().put("error", true).put("message", it.message) }
        else JSONObject().put("error", true).put("message", "Go engine not available")

    /** 1 if [password] decrypts the profile's private key, 0 if not, -1 if there is no inline key. */
    fun openvpnCheckKeyPassword(profile: String, password: String): Int =
        if (initialized) runCatching { openvpnCheckKey(profile, password) }.getOrDefault(-1) else -1

    /** Per-profile OpenVPN session status (go/openvpn Summary); empty when none run. */
    fun openvpnSessions(): org.json.JSONArray = if (initialized) runCatching { org.json.JSONArray(openvpnStatus()) }.getOrDefault(org.json.JSONArray()) else org.json.JSONArray()

    /** Recent log lines of a running OpenVPN session. */
    fun openvpnLogLines(id: String): List<String> = if (!initialized) emptyList() else runCatching {
        val arr = org.json.JSONArray(openvpnLog(id))
        List(arr.length()) { arr.getString(it) }
    }.getOrDefault(emptyList())

    /** Per-proxy HTTP/SOCKS5 status; empty when none run. */
    fun proxies(): org.json.JSONArray = if (initialized) runCatching { org.json.JSONArray(socksStatus()) }.getOrDefault(org.json.JSONArray()) else org.json.JSONArray()

    fun networkChanged() {
        if (initialized) notifyNetworkChanged()
    }

    fun stats(): JSONObject? = if (initialized) runCatching { JSONObject(engineStats()) }.getOrNull() else null

    @JvmStatic external fun version(): String
    @JvmStatic external fun echo(message: String): String
    @JvmStatic private external fun nativeInit(): Boolean
    @JvmStatic private external fun startEngine(fd: Int, config: String): String?
    @JvmStatic private external fun stopEngine()
    @JvmStatic private external fun setPolicy(policy: String): String?
    @JvmStatic private external fun tailnetStatus(): String
    @JvmStatic private external fun tailnetPeers(): String
    @JvmStatic private external fun resolveTailnetName(name: String): String
    @JvmStatic private external fun notifyNetworkChanged()
    @JvmStatic private external fun engineStats(): String
    @JvmStatic private external fun openvpnLinked(): Boolean
    @JvmStatic private external fun openvpnParse(profile: String): String
    @JvmStatic private external fun openvpnCheckKey(profile: String, password: String): Int
    @JvmStatic private external fun openvpnStatus(): String
    @JvmStatic private external fun openvpnLog(id: String): String
    @JvmStatic private external fun socksStatus(): String

    // --- Upcalls from Go. Names and signatures are bound in go/jni/main.go. ---

    @JvmStatic fun protect(fd: Int): Boolean = try {
        host?.protect(fd) ?: false
    } catch (_: Throwable) {
        false
    }

    @JvmStatic fun dnsQuery(query: ByteArray, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int, tcp: Boolean): ByteArray? = try {
        host?.dnsQuery(query, source, sourcePort, destination, destinationPort, tcp)
    } catch (_: Throwable) {
        null
    }

    @JvmStatic fun ownerUid(protocol: Int, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int): Int = try {
        host?.ownerUid(protocol, source, sourcePort, destination, destinationPort) ?: -1
    } catch (_: Throwable) {
        -1
    }

    @JvmStatic fun interfaces(): String = try {
        host?.interfaces() ?: "[]"
    } catch (_: Throwable) {
        "[]"
    }

    @JvmStatic fun onEngineStopped(reason: String?) {
        try {
            host?.onEngineStopped(reason ?: "engine stopped")
        } catch (_: Throwable) {
        }
    }

    /** One-line diagnostic for the status screen; never throws. */
    fun describe(): String = if (!available) "not bundled in this build" else try {
        val reply = echo("ping")
        "${version()} · echo ${if (reply == "go:ping") "ok" else "unexpected: $reply"}"
    } catch (e: Throwable) {
        "error: ${e.message}"
    }
}
