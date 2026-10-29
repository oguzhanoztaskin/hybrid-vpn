// C interface between the Go openvpn package and OpenVPN 3 Core (client.cpp).
// Strings returned by hv_ovpn_* are malloc'd; the caller frees them.

#ifndef HV_OVPN_H
#define HV_OVPN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// hv_ovpn_eval parses a profile without connecting. Returns JSON:
// {"error","message","autologin","username","friendly_name","profile_name","remote_host","remote_port",
//  "remote_proto","static_challenge","private_key_password","external_pki"}.
char *hv_ovpn_eval(const char *profile);

// hv_ovpn_new creates a client whose callbacks carry handle.
void *hv_ovpn_new(uintptr_t handle);

// hv_ovpn_configure loads the profile, credentials and private key password
// (empty when not needed). Returns NULL on success or an error message.
char *hv_ovpn_configure(void *client, const char *profile, const char *username, const char *password,
                        const char *key_password);

// hv_ovpn_check_key_password reports whether password decrypts the profile's
// inline private key: 1 yes, 0 no, -1 no readable <key> block.
int hv_ovpn_check_key_password(const char *profile, const char *password);

// hv_ovpn_connect runs the session and returns only after it ends (stop,
// fatal error). Returns JSON {"error","status","message"}.
char *hv_ovpn_connect(void *client);

// hv_ovpn_stop ends a running hv_ovpn_connect from any thread.
void hv_ovpn_stop(void *client);

// hv_ovpn_reconnect asks a running session to reconnect after seconds.
void hv_ovpn_reconnect(void *client, int seconds);

// hv_ovpn_info returns JSON with the current connection's server and VPN
// addresses (empty strings before the first connection).
char *hv_ovpn_info(void *client);

// hv_ovpn_stats fills bytes in, bytes out, packets in, packets out of the
// transport (encrypted side).
void hv_ovpn_stats(void *client, long long out[4]);

// hv_ovpn_counters returns the core's non-zero counters as "name=value ..."
// (errors and drops included), for diagnostics.
char *hv_ovpn_counters(void *client);

void hv_ovpn_free(void *client);

// Callbacks implemented in Go (native.go). All run on the hv_ovpn_connect thread.

// goOvpnProtect excludes a transport socket from the VPN; 0 means failure.
extern int goOvpnProtect(uintptr_t handle, int fd);
// goOvpnEstablish receives the pushed tunnel configuration (JSON) and the
// Go end of the packet socket, which it owns from then on. 0 means success.
extern int goOvpnEstablish(uintptr_t handle, char *config, int fd);
// goOvpnTeardown says the tunnel is gone; disconnect is true before the final stop.
extern void goOvpnTeardown(uintptr_t handle, int disconnect);
extern void goOvpnEvent(uintptr_t handle, char *name, char *info, int error, int fatal);
extern void goOvpnLog(uintptr_t handle, char *text);

#ifdef __cplusplus
}
#endif

#endif
