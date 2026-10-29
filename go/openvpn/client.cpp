//go:build openvpn3

// OpenVPN 3 Core client for the Go openvpn package (see ovpn.h).
//
// The core never sees a real TUN device. tun_builder_establish hands it one
// end of a packet socket pair and passes the other end, with the pushed
// configuration, to Go, which runs a userspace network stack on it. Transport
// sockets are protected from the VPN through goOvpnProtect before they connect.

#define OPENVPN_CORE_API_VISIBILITY_HIDDEN
#ifndef __ANDROID__
// Android selects the tun-builder path itself; host builds (tests) use the same path.
#define USE_TUN_BUILDER
#endif
#include <client/ovpncli.cpp>

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "ovpn.h"

namespace {

using namespace openvpn;

// Process-wide core initialisation (crypto library, time base).
ClientAPI::OpenVPNClientHelper &helper()
{
    static ClientAPI::OpenVPNClientHelper h;
    return h;
}

std::string quote(const std::string &s)
{
    std::string out = "\"";
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20)
            {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else
                out += static_cast<char>(c);
        }
    }
    return out + "\"";
}

const char *boolean(bool b)
{
    return b ? "true" : "false";
}

char *dup(const std::string &s)
{
    return strdup(s.c_str());
}

struct Prefix
{
    std::string address;
    int prefix;
    bool ipv6;
};

std::string prefixes(const std::vector<Prefix> &v)
{
    std::string out = "[";
    for (size_t i = 0; i < v.size(); ++i)
    {
        if (i)
            out += ",";
        out += "{\"address\":" + quote(v[i].address) + ",\"prefix\":" + std::to_string(v[i].prefix)
               + ",\"ipv6\":" + boolean(v[i].ipv6) + "}";
    }
    return out + "]";
}

std::string strings(const std::vector<std::string> &v)
{
    std::string out = "[";
    for (size_t i = 0; i < v.size(); ++i)
        out += (i ? "," : "") + quote(v[i]);
    return out + "]";
}

class Client : public ClientAPI::OpenVPNClient
{
  public:
    explicit Client(uintptr_t handle)
        : handle_(handle)
    {
    }

    // --- tun builder: collect the pushed configuration ---

    bool tun_builder_new() override
    {
        addresses_.clear();
        routes_.clear();
        excluded_.clear();
        dns_servers_.clear();
        dns_domains_.clear();
        search_domains_.clear();
        reroute4_ = reroute6_ = false;
        mtu_ = 0;
        remote_.clear();
        session_.clear();
        return true;
    }

    bool tun_builder_set_remote_address(const std::string &address, bool) override
    {
        remote_ = address;
        return true;
    }

    bool tun_builder_add_address(const std::string &address, int prefix, const std::string &, bool ipv6, bool) override
    {
        addresses_.push_back({address, prefix, ipv6});
        return true;
    }

    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override
    {
        // With emulated exclude routes the core passes explicit routes instead.
        if (flags & RGWFlags::EmulateExcludeRoutes)
            return true;
        reroute4_ = reroute4_ || ipv4;
        reroute6_ = reroute6_ || ipv6;
        return true;
    }

    bool tun_builder_add_route(const std::string &address, int prefix, int, bool ipv6) override
    {
        routes_.push_back({address, prefix, ipv6});
        return true;
    }

    bool tun_builder_exclude_route(const std::string &address, int prefix, int, bool ipv6) override
    {
        excluded_.push_back({address, prefix, ipv6});
        return true;
    }

    bool tun_builder_set_dns_options(const DnsOptions &dns) override
    {
        for (const auto &[priority, server] : dns.servers)
        {
            for (const auto &a : server.addresses)
                dns_servers_.push_back(a.address);
            for (const auto &d : server.domains)
                dns_domains_.push_back(d.domain);
        }
        for (const auto &d : dns.search_domains)
            search_domains_.push_back(d.domain);
        return true;
    }

    bool tun_builder_set_mtu(int mtu) override
    {
        mtu_ = mtu;
        return true;
    }

    bool tun_builder_set_session_name(const std::string &name) override
    {
        session_ = name;
        return true;
    }

    bool tun_builder_set_layer(int layer) override
    {
        return layer == 3; // no TAP
    }

    // The proxy, WINS and address-family settings are accepted and ignored:
    // they configure the OS, and nothing here routes through the OS.
    bool tun_builder_add_proxy_bypass(const std::string &) override
    {
        return true;
    }
    bool tun_builder_set_proxy_auto_config_url(const std::string &) override
    {
        return true;
    }
    bool tun_builder_set_proxy_http(const std::string &, int) override
    {
        return true;
    }
    bool tun_builder_set_proxy_https(const std::string &, int) override
    {
        return true;
    }
    bool tun_builder_add_wins_server(const std::string &) override
    {
        return true;
    }
    bool tun_builder_set_allow_family(int, bool) override
    {
        return true;
    }
    bool tun_builder_set_allow_local_dns(bool) override
    {
        return true;
    }
    bool tun_builder_set_route_metric_default(int) override
    {
        return true;
    }

    int tun_builder_establish() override
    {
        int sv[2];
#if defined(__linux__)
        // Datagram socket pairs on Linux queue at most net.unix.max_dgram_qlen
        // (often 10) packets; sequenced packets are bounded by the buffer only.
        const int type = SOCK_SEQPACKET;
#else
        const int type = SOCK_DGRAM;
#endif
        if (socketpair(AF_UNIX, type, 0, sv) != 0)
            return -1;
        for (int fd : sv)
        {
            int size = 1 << 20;
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
            fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        std::string cfg = "{\"addresses\":" + prefixes(addresses_)
                          + ",\"routes\":" + prefixes(routes_)
                          + ",\"excluded_routes\":" + prefixes(excluded_)
                          + ",\"reroute_ipv4\":" + boolean(reroute4_)
                          + ",\"reroute_ipv6\":" + boolean(reroute6_)
                          + ",\"mtu\":" + std::to_string(mtu_)
                          + ",\"remote\":" + quote(remote_)
                          + ",\"session\":" + quote(session_)
                          + ",\"dns_servers\":" + strings(dns_servers_)
                          + ",\"dns_domains\":" + strings(dns_domains_)
                          + ",\"search_domains\":" + strings(search_domains_)
#if defined(OPENVPN_PLATFORM_MAC)
                          + ",\"af_prefix\":true"
#else
                          + ",\"af_prefix\":false"
#endif
                          + "}";
        if (goOvpnEstablish(handle_, const_cast<char *>(cfg.c_str()), sv[1]) != 0)
        {
            close(sv[0]); // Go closed its end
            return -1;
        }
        return sv[0];
    }

    bool tun_builder_persist() override
    {
        return true; // keep the tunnel across reconnects when nothing changed
    }

    void tun_builder_teardown(bool disconnect) override
    {
        goOvpnTeardown(handle_, disconnect ? 1 : 0);
    }

    // --- everything else ---

    bool socket_protect(openvpn_io::detail::socket_type socket, std::string, bool) override
    {
        // The core leaves the transport socket at the system's default
        // buffer sizes (224 KiB on Android): a burst arriving while the
        // core's one thread is busy overflows it, and every drop is a loss
        // for TCP inside the tunnel. Larger buffers absorb the bursts; the
        // kernel caps them at net.core.rmem_max / wmem_max.
        int rcv = 4 << 20, snd = 2 << 20;
        setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
        setsockopt(socket, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        return goOvpnProtect(handle_, socket) != 0;
    }

    bool pause_on_connection_timeout() override
    {
        return false;
    }

    void event(const ClientAPI::Event &ev) override
    {
        goOvpnEvent(handle_, const_cast<char *>(ev.name.c_str()), const_cast<char *>(ev.info.c_str()), ev.error, ev.fatal);
    }

    void acc_event(const ClientAPI::AppCustomControlMessageEvent &) override
    {
    }

    void log(const ClientAPI::LogInfo &li) override
    {
        goOvpnLog(handle_, const_cast<char *>(li.text.c_str()));
    }

    void external_pki_cert_request(ClientAPI::ExternalPKICertRequest &req) override
    {
        req.error = true;
        req.errorText = "external PKI is not supported";
    }

    void external_pki_sign_request(ClientAPI::ExternalPKISignRequest &req) override
    {
        req.error = true;
        req.errorText = "external PKI is not supported";
    }

  private:
    uintptr_t handle_;
    std::vector<Prefix> addresses_, routes_, excluded_;
    std::vector<std::string> dns_servers_, dns_domains_, search_domains_;
    bool reroute4_ = false, reroute6_ = false;
    int mtu_ = 0;
    std::string remote_, session_;
};

ClientAPI::Config config(const char *profile)
{
    ClientAPI::Config c;
    c.content = profile;
    c.guiVersion = "HybridVPN";
    c.info = true;
    c.tunPersist = true;
    c.compressionMode = "asym"; // decompress if the server insists, never compress (VORACLE)
    return c;
}

std::string status_json(const ClientAPI::Status &s)
{
    return "{\"error\":" + std::string(boolean(s.error)) + ",\"status\":" + quote(s.status)
           + ",\"message\":" + quote(s.message) + "}";
}

} // namespace

extern "C" {

char *hv_ovpn_eval(const char *profile)
{
    try
    {
        const ClientAPI::EvalConfig e = helper().eval_config(config(profile));
        return dup("{\"error\":" + std::string(boolean(e.error))
                   + ",\"message\":" + quote(e.message)
                   + ",\"autologin\":" + boolean(e.autologin)
                   + ",\"username\":" + quote(e.userlockedUsername)
                   + ",\"friendly_name\":" + quote(e.friendlyName)
                   + ",\"profile_name\":" + quote(e.profileName)
                   + ",\"remote_host\":" + quote(e.remoteHost)
                   + ",\"remote_port\":" + quote(e.remotePort)
                   + ",\"remote_proto\":" + quote(e.remoteProto)
                   + ",\"static_challenge\":" + quote(e.staticChallenge)
                   + ",\"private_key_password\":" + boolean(e.privateKeyPasswordRequired)
                   + ",\"external_pki\":" + boolean(e.externalPki) + "}");
    }
    catch (const std::exception &ex)
    {
        return dup("{\"error\":true,\"message\":" + quote(ex.what()) + "}");
    }
}

void *hv_ovpn_new(uintptr_t handle)
{
    helper();
    return new Client(handle);
}

char *hv_ovpn_configure(void *client, const char *profile, const char *username, const char *password,
                        const char *key_password)
{
    auto *c = static_cast<Client *>(client);
    try
    {
        ClientAPI::Config cfg = config(profile);
        if (key_password)
            cfg.privateKeyPassword = key_password;
        const ClientAPI::EvalConfig e = c->eval_config(cfg);
        if (e.error)
            return dup(e.message.empty() ? "invalid profile" : e.message);
        if (e.externalPki)
            return dup("the profile has no client key (external PKI is not supported)");
        if (e.privateKeyPasswordRequired && (!key_password || !*key_password))
            return dup("the private key is encrypted and needs its password");
        if (!e.autologin)
        {
            if (!username || !*username)
                return dup("the profile needs a username and password");
            ClientAPI::ProvideCreds creds;
            creds.username = username;
            creds.password = password ? password : "";
            const ClientAPI::Status s = c->provide_creds(creds);
            if (s.error)
                return dup(s.message);
        }
        return nullptr;
    }
    catch (const std::exception &ex)
    {
        return dup(ex.what());
    }
}

char *hv_ovpn_connect(void *client)
{
    try
    {
        return dup(status_json(static_cast<Client *>(client)->connect()));
    }
    catch (const std::exception &ex)
    {
        return dup("{\"error\":true,\"status\":\"exception\",\"message\":" + quote(ex.what()) + "}");
    }
}

void hv_ovpn_stop(void *client)
{
    static_cast<Client *>(client)->stop();
}

void hv_ovpn_reconnect(void *client, int seconds)
{
    static_cast<Client *>(client)->reconnect(seconds);
}

char *hv_ovpn_info(void *client)
{
    const ClientAPI::ConnectionInfo i = static_cast<Client *>(client)->connection_info();
    return dup("{\"defined\":" + std::string(boolean(i.defined))
               + ",\"user\":" + quote(i.user)
               + ",\"server_host\":" + quote(i.serverHost)
               + ",\"server_port\":" + quote(i.serverPort)
               + ",\"server_proto\":" + quote(i.serverProto)
               + ",\"server_ip\":" + quote(i.serverIp)
               + ",\"vpn_ip4\":" + quote(i.vpnIp4)
               + ",\"vpn_ip6\":" + quote(i.vpnIp6)
               + ",\"gw4\":" + quote(i.gw4)
               + ",\"gw6\":" + quote(i.gw6) + "}");
}

void hv_ovpn_stats(void *client, long long out[4])
{
    const ClientAPI::TransportStats t = static_cast<Client *>(client)->transport_stats();
    out[0] = t.bytesIn;
    out[1] = t.bytesOut;
    out[2] = t.packetsIn;
    out[3] = t.packetsOut;
}

char *hv_ovpn_counters(void *client)
{
    auto *c = static_cast<Client *>(client);
    const std::vector<long long> v = c->stats_bundle();
    std::string out;
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i])
            out += ClientAPI::OpenVPNClient::stats_name(static_cast<int>(i)) + "=" + std::to_string(v[i]) + " ";
    return dup(out);
}

int hv_ovpn_check_key_password(const char *profile, const char *password)
{
    // The inline <key> block; files referenced by path are not supported anyway.
    const std::string text = profile;
    const size_t open = text.find("<key>"), close = text.find("</key>");
    if (open == std::string::npos || close == std::string::npos || close < open)
        return -1;
    const std::string pem = text.substr(open + 5, close - open - 5);
    BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio)
        return -1;
    // A non-null password callback argument: OpenSSL never prompts on a terminal.
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, const_cast<char *>(password ? password : ""));
    BIO_free(bio);
    ERR_clear_error();
    if (!key)
        return 0;
    EVP_PKEY_free(key);
    return 1;
}

void hv_ovpn_free(void *client)
{
    delete static_cast<Client *>(client);
}

} // extern "C"
