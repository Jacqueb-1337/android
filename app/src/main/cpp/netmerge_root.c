/*
 * Root TUN broker for Net-Merge Android.
 * Runs under Magisk su; app stays unprivileged and receives the TUN fd over an
 * authenticated local Unix socket (SCM_RIGHTS).
 *
 * The policy rule sits AFTER Android's per-UID VPN rules, but BEFORE its
 * physical-network fallback. Pinned android_setsocknetwork() sockets carry
 * fwmarks and bypass this rule, preventing recursive interception.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define IFACE "nmrg0"
#define TABLE "32013"
#define PREF "23123"
#define MTU "9000"

static int run(const char *const args[]) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        execv("/system/bin/ip", (char *const *)args);
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status) == 0 ? 0 : -1;
}
#define IP(...) run((const char *const[]) {"/system/bin/ip", __VA_ARGS__, NULL})

static void cleanup(void) {
    /* Scoped by BOTH priority and table: never delete Android's own rules. */
    IP("-4", "rule", "del", "pref", PREF, "fwmark", "0x0/0x1ffff", "iif", "lo", "lookup", TABLE);
    IP("-6", "rule", "del", "pref", PREF, "fwmark", "0x0/0x1ffff", "iif", "lo", "lookup", TABLE);
    IP("-4", "route", "flush", "table", TABLE);
    IP("-6", "route", "flush", "table", TABLE);
}
static int install(void) {
    /* Preserve LAN/loopback/tailnet addresses when not claimed by a VPN rule. */
    const char *skip4[] = {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
        "224.0.0.0/4", NULL
    };
    const char *skip6[] = {"fe80::/10", "fc00::/7", "ff00::/8", "::1/128", NULL};
    for (int i = 0; skip4[i]; i++)
        if (IP("-4", "route", "add", "throw", skip4[i], "table", TABLE)) return -1;
    for (int i = 0; skip6[i]; i++)
        if (IP("-6", "route", "add", "throw", skip6[i], "table", TABLE)) return -1;

    if (IP("-4", "route", "add", "default", "dev", IFACE, "table", TABLE)) return -1;
    if (IP("-6", "route", "add", "default", "dev", IFACE, "table", TABLE)) return -1;

    /* Policy rules are installed LAST, only after Go has opened the fd. */
    if (IP("-4", "rule", "add", "pref", PREF, "fwmark", "0x0/0x1ffff",
           "iif", "lo", "lookup", TABLE)) return -1;
    if (IP("-6", "rule", "add", "pref", PREF, "fwmark", "0x0/0x1ffff",
           "iif", "lo", "lookup", TABLE)) return -1;
    return 0;
}
static int send_fd(int sock, int fd) {
    char mark = 'F';
    struct iovec iov = {.iov_base = &mark, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}
int main(int argc, char **argv) {
    if (argc != 2 || !argv[1][0] || strlen(argv[1]) > 90) return 2;
    int lock = open("/data/local/tmp/netmerge-root.lock", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB)) {
        fprintf(stderr, "Net-Merge root helper already running\n");
        return 3;
    }
    int tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (tun < 0) { perror("open tun"); return 4; }
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(tun, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); return 5; }
    if (IP("link", "set", "dev", IFACE, "mtu", MTU, "up") ||
        IP("-4", "addr", "add", "198.18.0.1/24", "dev", IFACE) ||
        IP("-6", "addr", "add", "fd6e:6d65:7267::1/64", "dev", IFACE)) {
        fprintf(stderr, "could not configure root TUN\n");
        return 6;
    }
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 7;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path + 1, argv[1], strlen(argv[1]));
    socklen_t size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(argv[1]));
    if (connect(s, (struct sockaddr *)&addr, size)) { perror("connect"); return 8; }
    struct ucred peer = {0};
    socklen_t len = sizeof(peer);
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &peer, &len) ||
        peer.uid == 0) { fprintf(stderr, "invalid app peer\n"); return 9; }
    if (send_fd(s, tun)) { perror("send fd"); return 10; }

    char command = 0;
    if (read(s, &command, 1) != 1 || command != 'A') return 11;
    int ok = install();
    if (ok) cleanup();
    char reply = ok ? 'E' : 'R';
    if (write(s, &reply, 1) != 1) { cleanup(); return 12; }
    if (ok) return 13;
    /* On app crash the socket closes, automatically restoring Android routing. */
    while (read(s, &command, 1) > 0 && command != 'S') {}
    cleanup();
    close(s);
    close(tun);
    close(lock);
    return 0;
}

