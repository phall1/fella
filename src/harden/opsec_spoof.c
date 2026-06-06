#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <stdlib.h>

static int (*real_uname)(struct utsname *buf) = NULL;
static int (*real_sysinfo)(struct sysinfo *info) = NULL;

int uname(struct utsname *buf) {
    if (!real_uname) real_uname = dlsym(RTLD_NEXT, "uname");
    int rc = real_uname(buf);
    if (rc != 0) return rc;

    const char *r = getenv("FELLA_FAKE_RELEASE");
    const char *v = getenv("FELLA_FAKE_VERSION");
    const char *m = getenv("FELLA_FAKE_MACHINE");
    const char *s = getenv("FELLA_FAKE_SYSNAME");

    if (r) {
        strncpy(buf->release, r, sizeof(buf->release) - 1);
        buf->release[sizeof(buf->release) - 1] = '\0';
    }
    if (v) {
        strncpy(buf->version, v, sizeof(buf->version) - 1);
        buf->version[sizeof(buf->version) - 1] = '\0';
    }
    if (m) {
        strncpy(buf->machine, m, sizeof(buf->machine) - 1);
        buf->machine[sizeof(buf->machine) - 1] = '\0';
    }
    if (s) {
        strncpy(buf->sysname, s, sizeof(buf->sysname) - 1);
        buf->sysname[sizeof(buf->sysname) - 1] = '\0';
    }

    return 0;
}

int sysinfo(struct sysinfo *info) {
    if (!real_sysinfo) real_sysinfo = dlsym(RTLD_NEXT, "sysinfo");
    int rc = real_sysinfo(info);
    if (rc != 0) return rc;

    const char *u = getenv("FELLA_FAKE_UPTIME");
    if (u) {
        long up = atol(u);
        info->uptime = up;
    }
    return 0;
}
