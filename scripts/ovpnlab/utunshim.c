// utunshim: lets an unprivileged OpenVPN 2 server on macOS use a userspace
// "utun" device, for the local OpenVPN lab (go/cmd/ovpnlab). Loaded with
// DYLD_INSERT_LIBRARIES; never part of the app.
//
// Opening utun (socket(PF_SYSTEM) + CTLIOCGINFO + connect + UTUN_OPT_IFNAME)
// needs root. The shim answers those calls itself and returns a Unix datagram
// socket bound to $HV_UTUN_LOCAL and connected to $HV_UTUN_PEER, where
// ovpnlab runs a userspace network stack. Framing is utun's: a 4-byte address
// family header, then one IP packet. Run the server with --ifconfig-noexec.

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/un.h>
#include <unistd.h>
#include <net/if_utun.h>

#define INTERPOSE(replacement, replacee)                                                         \
    __attribute__((used)) static struct {                                                        \
        const void *r;                                                                           \
        const void *e;                                                                           \
    } interpose_##replacee __attribute__((section("__DATA,__interpose"))) = {(const void *)&replacement, \
                                                                             (const void *)&replacee}

static int fake_fd = -1;

static int unix_addr(const char *path, struct sockaddr_un *a)
{
    if (!path || strlen(path) >= sizeof(a->sun_path))
        return -1;
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    strcpy(a->sun_path, path);
    return 0;
}

static int shim_socket(int domain, int type, int protocol)
{
    if (domain != PF_SYSTEM || protocol != SYSPROTO_CONTROL)
        return socket(domain, type, protocol);
    struct sockaddr_un local, peer;
    if (unix_addr(getenv("HV_UTUN_LOCAL"), &local) || unix_addr(getenv("HV_UTUN_PEER"), &peer))
    {
        fprintf(stderr, "utunshim: set HV_UTUN_LOCAL and HV_UTUN_PEER\n");
        errno = EACCES;
        return -1;
    }
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;
    int size = 1 << 20;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    unlink(local.sun_path);
    if (bind(s, (struct sockaddr *)&local, sizeof(local)) || connect(s, (struct sockaddr *)&peer, sizeof(peer)))
    {
        fprintf(stderr, "utunshim: %s -> %s: %s\n", local.sun_path, peer.sun_path, strerror(errno));
        close(s);
        return -1;
    }
    fake_fd = s;
    return s;
}

static int shim_ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (fd == fake_fd && request == CTLIOCGINFO)
    {
        ((struct ctl_info *)arg)->ctl_id = 1;
        return 0;
    }
    return ioctl(fd, request, arg);
}

static int shim_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (fd == fake_fd && addr->sa_family == AF_SYSTEM)
        return 0;
    return connect(fd, addr, len);
}

static int shim_getsockopt(int fd, int level, int name, void *value, socklen_t *len)
{
    if (fd == fake_fd && level == SYSPROTO_CONTROL && name == UTUN_OPT_IFNAME)
    {
        const char *ifname = "utun99";
        if (*len < strlen(ifname) + 1)
        {
            errno = EINVAL;
            return -1;
        }
        strcpy(value, ifname);
        *len = (socklen_t)strlen(ifname) + 1;
        return 0;
    }
    return getsockopt(fd, level, name, value, len);
}

INTERPOSE(shim_socket, socket);
INTERPOSE(shim_ioctl, ioctl);
INTERPOSE(shim_connect, connect);
INTERPOSE(shim_getsockopt, getsockopt);
