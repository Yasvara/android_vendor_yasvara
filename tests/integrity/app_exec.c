// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0
//
// Runs a command, or reads properties, with an app's identity: uid, gids, SELinux context and,
// with --pid, its mount namespace. Run as root (adb root); a test tool, never in a product.
//
//   yasvara_app_exec --pid <pid> -- <cmd> [args...]
//   yasvara_app_exec --uid <uid> [--context <ctx>] [--name <process>] --props <name>...
//
// --props reads each property through libc.so (get, then find + read_callback) in a fresh child,
// so libc's per-process app detection sees the final uid and process name, as in a real app.
// Prints "<name>\tget\t<value>" and "<name>\tfind\t<value>|<absent>" per property.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char* what) {
    fprintf(stderr, "yasvara_app_exec: %s: %s\n", what, strerror(errno));
    exit(126);
}

static int read_file(const char* path, char* buf, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

// The first number after "<key>:" in /proc/<pid>/status, or the whole list for "Groups".
static const char* status_field(const char* status, const char* key) {
    size_t len = strlen(key);
    for (const char* p = status; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
        if (strncmp(p, key, len) == 0 && p[len] == ':') return p + len + 1;
    }
    return NULL;
}

static void become_pid(pid_t pid, uid_t* uid, char* context, size_t context_size) {
    char path[64], status[4096];
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);
    int ns = open(path, O_RDONLY | O_CLOEXEC);
    if (ns < 0 || setns(ns, CLONE_NEWNS) != 0) die("mount namespace");
    close(ns);

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    if (read_file(path, status, sizeof(status)) < 0) die(path);
    const char* u = status_field(status, "Uid");
    const char* g = status_field(status, "Gid");
    const char* groups = status_field(status, "Groups");
    if (!u || !g) die("status");
    *uid = (uid_t)strtoul(u, NULL, 10);
    gid_t gid = (gid_t)strtoul(g, NULL, 10);

    gid_t list[64];
    int n = 0;
    for (char* end; groups && n < 64; groups = end) {
        unsigned long v = strtoul(groups, &end, 10);
        if (end == groups || *groups == '\n') break;
        list[n++] = (gid_t)v;
    }
    if (setgroups(n, list) != 0 || setresgid(gid, gid, gid) != 0) die("gids");

    snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
    int len = read_file(path, context, context_size);
    if (len <= 0) die(path);
    context[strcspn(context, "\n")] = '\0';
}

static void read_cb(void* cookie, const char* name, const char* value, uint32_t serial) {
    (void)name;
    (void)serial;
    strlcpy(cookie, value, PROP_VALUE_MAX);
}

static int read_props(char** names) {
    pid_t child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        for (; *names; ++names) {
            char value[PROP_VALUE_MAX] = "";
            __system_property_get(*names, value);
            printf("%s\tget\t%s\n", *names, value);
            const prop_info* pi = __system_property_find(*names);
            if (pi) {
                __system_property_read_callback(pi, read_cb, value);
                printf("%s\tfind\t%s\n", *names, value);
            } else {
                printf("%s\tfind\t<absent>\n", *names);
            }
        }
        fflush(stdout);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) < 0) die("waitpid");
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "yasvara_app_exec: reader killed by signal %d\n", WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    return WEXITSTATUS(status);
}

int main(int argc, char** argv) {
    pid_t pid = 0;
    uid_t uid = 0;
    const char* context = NULL;
    const char* name = NULL;
    char** props = NULL;
    char** cmd = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc) pid = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--uid") && i + 1 < argc) uid = (uid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--context") && i + 1 < argc) context = argv[++i];
        else if (!strcmp(argv[i], "--name") && i + 1 < argc) name = argv[++i];
        else if (!strcmp(argv[i], "--props")) { props = argv + i + 1; break; }
        else if (!strcmp(argv[i], "--")) { cmd = argv + i + 1; break; }
        else { fprintf(stderr, "usage: see app_exec.c\n"); return 2; }
    }
    if ((!pid && !uid) || (!props && !(cmd && *cmd))) {
        fprintf(stderr, "usage: see app_exec.c\n");
        return 2;
    }

    // libc reads the process name from /proc/self/cmdline: argv[0] must already be it.
    if (name && strcmp(argv[0], name) != 0) {
        argv[0] = (char*)name;
        execv("/proc/self/exe", argv);
        die("re-exec");
    }

    char own_context[256];
    if (pid) {
        become_pid(pid, &uid, own_context, sizeof(own_context));
        if (!context) context = own_context;
    } else {
        gid_t groups[] = {3003, 9997, (gid_t)(uid % 100000 - 10000 + 50000)};
        if (setgroups(3, groups) != 0 || setresgid(uid, uid, uid) != 0) die("gids");
        if (!context) {
            unsigned app = (uid % 100000) - 10000;
            snprintf(own_context, sizeof(own_context),
                     "u:r:untrusted_app:s0:c%u,c%u,c512,c768", app & 0xff, 256 + ((app >> 8) & 0xff));
            context = own_context;
        }
    }
    if (setresuid(uid, uid, uid) != 0) die("uid");

    // After the uid change, so the new domain needs no capabilities; su is permissive.
    int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
    if (fd < 0 || write(fd, context, strlen(context)) < 0) die("setcon");
    close(fd);

    if (props) return read_props(props);
    execv(cmd[0], cmd);
    die(cmd[0]);
}
