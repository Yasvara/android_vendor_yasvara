// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0
// On-device kernel procfs/statfs hiding & normalization verifier. Runs under both an app UID
// (e.g. u0_a*) and a system daemon UID (e.g. 1000) via yasvara_app_exec, exercising both libc
// wrappers and raw svc #0 syscall() paths. Never in a product image.

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef EROFS_SUPER_MAGIC_V1
#define EROFS_SUPER_MAGIC_V1 0xe0f5e1e2UL
#endif
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630UL
#endif
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0UL
#endif
#ifndef ST_RDONLY
#define ST_RDONLY 0x0001UL
#endif

static long direct_syscall4(long nr, long a0, long a1, long a2, long a3) {
#if defined(__aarch64__)
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                   : "memory", "cc");
  if (x0 < 0 && x0 >= -4095) {
    errno = (int)(-x0);
    return -1;
  }
  return x0;
#else
  return syscall(nr, a0, a1, a2, a3);
#endif
}

static int raw_openat(int dirfd, const char* path, int flags) {
  return (int)direct_syscall4(__NR_openat, dirfd, (long)path, flags, 0);
}

static int raw_fstat(int fd, struct stat* st) {
  return (int)direct_syscall4(__NR_fstat, fd, (long)st, 0, 0);
}

static int raw_statfs(const char* path, struct statfs* sfs) {
  return (int)direct_syscall4(__NR_statfs, (long)path, (long)sfs, 0, 0);
}

static int raw_fstatfs(int fd, struct statfs* sfs) {
  return (int)direct_syscall4(__NR_fstatfs, fd, (long)sfs, 0, 0);
}

static int raw_newfstatat(int dirfd, const char* path, struct stat* st, int flags) {
  return (int)direct_syscall4(__NR_newfstatat, dirfd, (long)path, (long)st, flags);
}

static int raw_faccessat(int dirfd, const char* path, int mode) {
  return (int)direct_syscall4(__NR_faccessat, dirfd, (long)path, mode, 0);
}

static int raw_getdents64(int fd, void* buf, size_t count) {
  return (int)direct_syscall4(__NR_getdents64, fd, (long)buf, (long)count, 0);
}

static int raw_connect(int fd, const void* addr, size_t len) {
  return (int)direct_syscall4(__NR_connect, fd, (long)addr, (long)len, 0);
}

static char* read_all_fd(int fd, size_t* out_len, bool use_raw) {
  size_t cap = 65536;
  size_t len = 0;
  char* buf = (char*)malloc(cap);
  if (!buf) abort();
  for (;;) {
    if (len + 4096 + 1 > cap) {
      cap *= 2;
      buf = (char*)realloc(buf, cap);
      if (!buf) abort();
    }
    ssize_t n = use_raw
                    ? (ssize_t)direct_syscall4(__NR_read, fd, (long)(buf + len), 4096, 0)
                    : read(fd, buf + len, 4096);
    if (n < 0) {
      if (errno == EINTR) continue;
      free(buf);
      return NULL;
    }
    if (n == 0) break;
    len += (size_t)n;
  }
  buf[len] = '\0';
  if (out_len) *out_len = len;
  return buf;
}

static int check_proc_maps_metadata(bool use_raw) {
  int fd = use_raw ? raw_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY)
                   : open("/proc/self/maps", O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "FAIL(%s): open /proc/self/maps errno=%d\n",
            use_raw ? "raw" : "libc", errno);
    return 1;
  }

  char fd_link_path[64];
  char target[PATH_MAX];
  snprintf(fd_link_path, sizeof(fd_link_path), "/proc/self/fd/%d", fd);
  ssize_t link_len =
      use_raw ? (ssize_t)direct_syscall4(__NR_readlinkat, AT_FDCWD, (long)fd_link_path,
                                         (long)target, (long)(sizeof(target) - 1))
              : readlinkat(AT_FDCWD, fd_link_path, target, sizeof(target) - 1);
  if (link_len < 0) {
    fprintf(stderr, "FAIL(%s): readlink %s errno=%d\n",
            use_raw ? "raw" : "libc", fd_link_path, errno);
    close(fd);
    return 1;
  }
  target[link_len] = '\0';

  char expected[64];
  snprintf(expected, sizeof(expected), "/proc/%d/maps", (int)getpid());
  if (strcmp(target, expected) != 0) {
    fprintf(stderr, "FAIL(%s): readlink mismatch got=%s expected=%s\n",
            use_raw ? "raw" : "libc", target, expected);
    close(fd);
    return 1;
  }

  struct stat st;
  memset(&st, 0x5a, sizeof(st));
  int rc = use_raw ? raw_fstat(fd, &st) : fstat(fd, &st);
  if (rc != 0 || st.st_size != 0) {
    fprintf(stderr, "FAIL(%s): fstat maps st_size=%lld rc=%d\n",
            use_raw ? "raw" : "libc", (long long)st.st_size, rc);
    close(fd);
    return 1;
  }

  struct statfs sfs;
  memset(&sfs, 0, sizeof(sfs));
  rc = use_raw ? raw_fstatfs(fd, &sfs) : fstatfs(fd, &sfs);
  if (rc != 0 || (unsigned long)sfs.f_type != PROC_SUPER_MAGIC) {
    fprintf(stderr, "FAIL(%s): fstatfs maps f_type=0x%lx expected=0x%lx\n",
            use_raw ? "raw" : "libc", (unsigned long)sfs.f_type, PROC_SUPER_MAGIC);
    close(fd);
    return 1;
  }

  close(fd);
  return 0;
}

static bool has_case_substr(const char* hay, const char* needle) {
  size_t nlen = strlen(needle);
  for (const char* p = hay; *p; p++) {
    size_t i = 0;
    while (i < nlen && p[i] &&
           tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == nlen) return true;
  }
  return false;
}

static int verify_smap_vma(bool use_raw, bool is_app, bool vma_exec,
                           bool is_dirty_probe, uint64_t rss, uint64_t sc,
                           uint64_t sd, uint64_t pc, uint64_t pd,
                           uint64_t pss_d, uint64_t swap, uint64_t swap_pss,
                           bool* saw_dirty_probe, uint64_t* dirty_probe_pdirty) {
  if (sc + sd + pc + pd != rss) {
    fprintf(stderr, "FAIL(%s): Rss mismatch %" PRIu64 " != %" PRIu64 "\n",
            use_raw ? "raw" : "libc", rss, sc + sd + pc + pd);
    return 1;
  }
  if (is_app && vma_exec &&
      (sd != 0 || pd != 0 || pss_d != 0 || swap != 0 || swap_pss != 0)) {
    fprintf(stderr,
            "FAIL(%s): non-zero dirty/swap on r-xp VMA (sd=%" PRIu64 " pd=%" PRIu64
            " pss_d=%" PRIu64 " swap=%" PRIu64 " swappss=%" PRIu64 ")\n",
            use_raw ? "raw" : "libc", sd, pd, pss_d, swap, swap_pss);
    return 1;
  }
  if (is_dirty_probe) {
    *saw_dirty_probe = true;
    *dirty_probe_pdirty = pd;
  }
  return 0;
}

static int check_smaps_stream(bool use_raw, bool is_app, uintptr_t dirty_exec_addr,
                              const char* hidden_marker) {
  int fd = use_raw ? raw_openat(AT_FDCWD, "/proc/self/smaps", O_RDONLY)
                   : open("/proc/self/smaps", O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "FAIL(%s): open /proc/self/smaps errno=%d\n",
            use_raw ? "raw" : "libc", errno);
    return 1;
  }
  char* text = read_all_fd(fd, NULL, use_raw);
  close(fd);
  if (!text) return 1;

  bool saw_hidden = has_case_substr(text, "xposed_smoke");
  if (hidden_marker && has_case_substr(text, hidden_marker)) saw_hidden = true;
  if (is_app && saw_hidden) {
    fprintf(stderr, "FAIL(%s): hidden marker exposed in smaps for app uid\n",
            use_raw ? "raw" : "libc");
    free(text);
    return 1;
  }
  if (!is_app && !saw_hidden) {
    fprintf(stderr, "FAIL(%s): hidden marker unexpectedly stripped for daemon uid\n",
            use_raw ? "raw" : "libc");
    free(text);
    return 1;
  }

  bool in_vma = false;
  bool vma_exec = false;
  bool is_dirty_probe = false;
  bool saw_dirty_probe = false;
  uint64_t dirty_probe_pdirty = UINT64_MAX;
  uint64_t rss = 0, sc = 0, sd = 0, pc = 0, pd = 0, pss_d = 0, swap = 0, swap_pss = 0;

  char* saveptr = NULL;
  for (char* line = strtok_r(text, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
    uintptr_t s = 0, e = 0;
    char perms[8] = "";
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &s, &e, perms) == 3 &&
        strchr(line, '-') && (strchr(perms, 'r') || strchr(perms, '-'))) {
      if (in_vma &&
          verify_smap_vma(use_raw, is_app, vma_exec, is_dirty_probe, rss, sc, sd, pc, pd,
                          pss_d, swap, swap_pss, &saw_dirty_probe, &dirty_probe_pdirty) != 0) {
        free(text);
        return 1;
      }
      in_vma = true;
      vma_exec = strchr(perms, 'x') != NULL;
      is_dirty_probe = (dirty_exec_addr >= s && dirty_exec_addr < e);
      rss = sc = sd = pc = pd = pss_d = swap = swap_pss = 0;
    } else if (in_vma) {
      uint64_t val = 0;
      if (sscanf(line, "Rss: %" SCNu64 " kB", &val) == 1) rss = val;
      else if (sscanf(line, "Pss_Dirty: %" SCNu64 " kB", &val) == 1) pss_d = val;
      else if (sscanf(line, "Shared_Clean: %" SCNu64 " kB", &val) == 1) sc = val;
      else if (sscanf(line, "Shared_Dirty: %" SCNu64 " kB", &val) == 1) sd = val;
      else if (sscanf(line, "Private_Clean: %" SCNu64 " kB", &val) == 1) pc = val;
      else if (sscanf(line, "Private_Dirty: %" SCNu64 " kB", &val) == 1) pd = val;
      else if (sscanf(line, "Swap: %" SCNu64 " kB", &val) == 1) swap = val;
      else if (sscanf(line, "SwapPss: %" SCNu64 " kB", &val) == 1) swap_pss = val;
    }
  }
  if (in_vma &&
      verify_smap_vma(use_raw, is_app, vma_exec, is_dirty_probe, rss, sc, sd, pc, pd,
                      pss_d, swap, swap_pss, &saw_dirty_probe, &dirty_probe_pdirty) != 0) {
    free(text);
    return 1;
  }
  free(text);

  if (!saw_dirty_probe) {
    fprintf(stderr, "FAIL(%s): probe r-xp VMA missing from smaps\n",
            use_raw ? "raw" : "libc");
    return 1;
  }
  if (is_app && dirty_probe_pdirty != 0) {
    fprintf(stderr, "FAIL(%s): probe r-xp VMA Private_Dirty=%" PRIu64 " expected 0\n",
            use_raw ? "raw" : "libc", dirty_probe_pdirty);
    return 1;
  }
  if (!is_app && dirty_probe_pdirty == 0) {
    fprintf(stderr, "FAIL(%s): daemon uid saw folded Private_Dirty=0 on dirty probe\n",
            use_raw ? "raw" : "libc");
    return 1;
  }
  return 0;
}

static int check_maps_hidden(bool use_raw, bool is_app, const char* hidden_marker) {
  int fd = use_raw ? raw_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY)
                   : open("/proc/self/maps", O_RDONLY);
  if (fd < 0) return 1;
  char* text = read_all_fd(fd, NULL, use_raw);
  close(fd);
  if (!text) return 1;

  bool saw = has_case_substr(text, "xposed_smoke") ||
             (hidden_marker && has_case_substr(text, hidden_marker));
  free(text);
  if (is_app && saw) {
    fprintf(stderr, "FAIL(%s): hidden marker exposed in maps for app uid\n",
            use_raw ? "raw" : "libc");
    return 1;
  }
  if (!is_app && !saw) {
    fprintf(stderr, "FAIL(%s): hidden marker missing from maps for daemon uid\n",
            use_raw ? "raw" : "libc");
    return 1;
  }
  return 0;
}

static bool is_opt_ro(const char* opts) {
  return strncmp(opts, "ro,", 3) == 0 || strcmp(opts, "ro") == 0;
}

static bool is_system_target(const char* t) {
  static const char* const kSys[] = {
      "/", "/system", "/vendor", "/product", "/system_ext", "/odm", "/apex",
  };
  for (size_t i = 0; i < sizeof(kSys) / sizeof(kSys[0]); i++) {
    if (strcmp(t, kSys[i]) == 0) return true;
  }
  return false;
}

static int check_mount_stream(const char* path, bool use_raw, bool is_app, int mode) {
  // mode: 0 = mounts, 1 = mountinfo, 2 = mountstats
  int fd = use_raw ? raw_openat(AT_FDCWD, path, O_RDONLY) : open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "FAIL(%s): open %s errno=%d\n", use_raw ? "raw" : "libc", path, errno);
    return 1;
  }
  char* text = read_all_fd(fd, NULL, use_raw);
  close(fd);
  if (!text) return 1;

  static const char* const kForbidden[] = {
      "/mnt/scratch", "/dev/block/mapper/scratch", "overlayfs_loop", "modules.img",
      "/data/adb",    "magisk",                    "kernelsu",       "apatch",
      "/debug_ramdisk", "/patch_hw",               "/dev/meta_hybird_mnt",
  };

  int rc = 0;
  char* saveptr = NULL;
  for (char* line = strtok_r(text, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
    if (!is_app) continue;

    for (size_t i = 0; i < sizeof(kForbidden) / sizeof(kForbidden[0]); i++) {
      if (has_case_substr(line, kForbidden[i])) {
        fprintf(stderr, "FAIL(%s): forbidden marker '%s' in %s: %s\n",
                use_raw ? "raw" : "libc", kForbidden[i], path, line);
        rc = 1;
        goto done;
      }
    }

    if (mode == 0) {
      char dev[128], target[256], fstype[64], opts[512];
      if (sscanf(line, "%127s %255s %63s %511s", dev, target, fstype, opts) == 4) {
        if (strcmp(fstype, "overlay") == 0 || strcmp(fstype, "overlayfs") == 0 ||
            (strcmp(fstype, "tmpfs") == 0 && strcmp(target, "/sbin") == 0)) {
          fprintf(stderr, "FAIL(%s): hidden fstype/sbin in %s: %s\n",
                  use_raw ? "raw" : "libc", path, line);
          rc = 1;
          goto done;
        }
        if (is_system_target(target) && !is_opt_ro(opts)) {
          fprintf(stderr, "FAIL(%s): system target %s not ro in mounts: %s\n",
                  use_raw ? "raw" : "libc", target, opts);
          rc = 1;
          goto done;
        }
      }
    } else if (mode == 1) {
      char* dash = strstr(line, " - ");
      if (dash) {
        char m_id[32], p_id[32], devno[32], root[256], target[256], mnt_opts[512];
        if (sscanf(line, "%31s %31s %31s %255s %255s %511s", m_id, p_id, devno, root, target,
                   mnt_opts) == 6) {
          char fstype[64], src[128], sb_opts[512];
          if (sscanf(dash + 3, "%63s %127s %511s", fstype, src, sb_opts) == 3) {
            if (strcmp(fstype, "overlay") == 0 || strcmp(fstype, "overlayfs") == 0 ||
                (strcmp(fstype, "tmpfs") == 0 && strcmp(target, "/sbin") == 0)) {
              fprintf(stderr, "FAIL(%s): hidden mountinfo line: %s\n",
                      use_raw ? "raw" : "libc", line);
              rc = 1;
              goto done;
            }
            if (is_system_target(target) && (!is_opt_ro(mnt_opts) || !is_opt_ro(sb_opts))) {
              fprintf(stderr, "FAIL(%s): system target %s not ro in mountinfo (%s | %s)\n",
                      use_raw ? "raw" : "libc", target, mnt_opts, sb_opts);
              rc = 1;
              goto done;
            }
          }
        }
      }
    } else if (mode == 2) {
      if (strstr(line, "with fstype overlay") || strstr(line, "mounted on /sbin with fstype tmpfs")) {
        fprintf(stderr, "FAIL(%s): hidden mountstats line: %s\n",
                use_raw ? "raw" : "libc", line);
        rc = 1;
        goto done;
      }
    }
  }

done:
  free(text);
  return rc;
}

static int check_statfs_paths(bool is_app) {
  static const char* const kPaths[] = {
      "/system", "/vendor", "/product", "/system_ext", "/odm",
  };
  for (size_t i = 0; i < sizeof(kPaths) / sizeof(kPaths[0]); i++) {
    const char* p = kPaths[i];
    for (int raw = 0; raw <= 1; raw++) {
      struct statfs sfs;
      memset(&sfs, 0, sizeof(sfs));
      int rc = raw ? raw_statfs(p, &sfs) : statfs(p, &sfs);
      if (rc != 0) continue;

      if (is_app) {
        if ((unsigned long)sfs.f_type == OVERLAYFS_SUPER_MAGIC) {
          fprintf(stderr, "FAIL(%s): statfs(%s) still OVERLAYFS_SUPER_MAGIC\n",
                  raw ? "raw" : "libc", p);
          return 1;
        }
        if ((unsigned long)sfs.f_type == EROFS_SUPER_MAGIC_V1) {
          if ((sfs.f_flags & ST_RDONLY) == 0 || sfs.f_bfree != 0 || sfs.f_bavail != 0) {
            fprintf(stderr,
                    "FAIL(%s): statfs(%s) erofs flags=0x%lx bfree=%" PRIu64 " bavail=%" PRIu64 "\n",
                    raw ? "raw" : "libc", p, (unsigned long)sfs.f_flags,
                    (uint64_t)sfs.f_bfree, (uint64_t)sfs.f_bavail);
            return 1;
          }
        }
      }

      int fd = open(p, O_RDONLY | O_DIRECTORY);
      if (fd >= 0) {
        struct statfs fsfs;
        memset(&fsfs, 0, sizeof(fsfs));
        rc = raw ? raw_fstatfs(fd, &fsfs) : fstatfs(fd, &fsfs);
        close(fd);
        if (rc == 0 && is_app && (unsigned long)fsfs.f_type == OVERLAYFS_SUPER_MAGIC) {
          fprintf(stderr, "FAIL(%s): fstatfs(%s) still OVERLAYFS_SUPER_MAGIC\n",
                  raw ? "raw" : "libc", p);
          return 1;
        }
      }

      if (!raw) {
        printf("STATFS uid=%u path=%s f_type=0x%lx f_flags=0x%lx bfree=%" PRIu64 " bavail=%" PRIu64
               "\n",
               (unsigned)getuid(), p, (unsigned long)sfs.f_type, (unsigned long)sfs.f_flags,
               (uint64_t)sfs.f_bfree, (uint64_t)sfs.f_bavail);
      }
    }
  }
  return 0;
}

struct linux_dirent64_probe {
  uint64_t d_ino;
  int64_t d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

static bool dir_contains_entry(const char* dirpath, const char* target, bool use_raw) {
  int fd = use_raw ? raw_openat(AT_FDCWD, dirpath, O_RDONLY | O_DIRECTORY)
                   : open(dirpath, O_RDONLY | O_DIRECTORY);
  if (fd < 0) return false;
  char buf[8192];
  bool found = false;
  for (;;) {
    int n = use_raw ? raw_getdents64(fd, buf, sizeof(buf))
                    : (int)syscall(__NR_getdents64, fd, buf, sizeof(buf));
    if (n <= 0) break;
    for (int pos = 0; pos < n;) {
      struct linux_dirent64_probe* d = (struct linux_dirent64_probe*)(buf + pos);
      if (d->d_reclen == 0 || pos + d->d_reclen > n) break;
      if (strcmp(d->d_name, target) == 0) {
        found = true;
        break;
      }
      pos += d->d_reclen;
    }
    if (found) break;
  }
  close(fd);
  return found;
}

static int check_kernel_policy_and_adb_hide(bool use_raw, bool is_app) {
  static const char* const kHiddenPaths[] = {
      "/sys/fs/selinux/policy",
      "/vendor/etc/selinux/vendor_sepolicy.cil",
      "/system/addon.d",
      "/system_ext/bin/adb_root",
      "/dev/socket/adbd",
  };
  for (size_t i = 0; i < sizeof(kHiddenPaths) / sizeof(kHiddenPaths[0]); i++) {
    const char* p = kHiddenPaths[i];
    struct stat st;
    errno = 0;
    int s_rc = use_raw ? raw_newfstatat(AT_FDCWD, p, &st, 0) : stat(p, &st);
    int s_err = errno;
    errno = 0;
    int a_rc = use_raw ? raw_faccessat(AT_FDCWD, p, F_OK) : access(p, F_OK);
    int a_err = errno;
    errno = 0;
    int o_fd = use_raw ? raw_openat(AT_FDCWD, p, O_RDONLY) : open(p, O_RDONLY);
    int o_err = errno;
    if (o_fd >= 0) close(o_fd);

    if (is_app) {
      if (s_rc != -1 || s_err != ENOENT) {
        fprintf(stderr, "FAIL(%s): app stat(%s) rc=%d errno=%d (expected ENOENT)\n",
                use_raw ? "raw" : "libc", p, s_rc, s_err);
        return 1;
      }
      if (a_rc != -1 || a_err != ENOENT) {
        fprintf(stderr, "FAIL(%s): app access(%s) rc=%d errno=%d (expected ENOENT)\n",
                use_raw ? "raw" : "libc", p, a_rc, a_err);
        return 1;
      }
      if (o_fd != -1 || o_err != ENOENT) {
        fprintf(stderr, "FAIL(%s): app open(%s) fd=%d errno=%d (expected ENOENT)\n",
                use_raw ? "raw" : "libc", p, o_fd, o_err);
        return 1;
      }
    } else {
      if (s_rc != 0) {
        fprintf(stderr, "FAIL(%s): daemon stat(%s) failed errno=%d\n",
                use_raw ? "raw" : "libc", p, s_err);
        return 1;
      }
    }
  }

  // Directory listing consistency for /system (addon.d), /dev/socket (adbd), /vendor/etc/selinux.
  bool saw_addon = dir_contains_entry("/system", "addon.d", use_raw);
  bool saw_adbd = dir_contains_entry("/dev/socket", "adbd", use_raw);
  bool saw_vsel = dir_contains_entry("/vendor/etc/selinux", "vendor_sepolicy.cil", use_raw);
  if (is_app && (saw_addon || saw_adbd || saw_vsel)) {
    fprintf(stderr, "FAIL(%s): app getdents64 leaked addon=%d adbd=%d vsel=%d\n",
            use_raw ? "raw" : "libc", saw_addon, saw_adbd, saw_vsel);
    return 1;
  }
  if (!is_app && (!saw_addon || !saw_adbd || !saw_vsel)) {
    fprintf(stderr, "FAIL(%s): daemon getdents64 missing addon=%d adbd=%d vsel=%d\n",
            use_raw ? "raw" : "libc", saw_addon, saw_adbd, saw_vsel);
    return 1;
  }

  // Abstract @jdwp-control connect() must return ECONNREFUSED for app (including raw svc #0).
  int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sfd >= 0) {
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    un.sun_path[0] = '\0';
    memcpy(un.sun_path + 1, "jdwp-control", 12);
    size_t addrlen = offsetof(struct sockaddr_un, sun_path) + 1 + 12;
    errno = 0;
    int c_rc = use_raw ? raw_connect(sfd, &un, addrlen) : connect(sfd, (struct sockaddr*)&un, addrlen);
    int c_err = errno;
    close(sfd);
    if (is_app && (c_rc != -1 || c_err != ECONNREFUSED)) {
      fprintf(stderr, "FAIL(%s): app connect(@jdwp-control) rc=%d errno=%d (expected ECONNREFUSED)\n",
              use_raw ? "raw" : "libc", c_rc, c_err);
      return 1;
    }
  }
  return 0;
}

int main(int argc, char** argv) {
  bool forced_mode = false;
  bool expected_app = ((getuid() % 100000U) >= 10000U);
  const char* map_file = NULL;
  const char* hidden_marker = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--expect-app") == 0) {
      forced_mode = true;
      expected_app = true;
    } else if (strcmp(argv[i], "--expect-daemon") == 0) {
      forced_mode = true;
      expected_app = false;
    } else if (strcmp(argv[i], "--map-file") == 0 && i + 1 < argc) {
      map_file = argv[++i];
    } else if (strcmp(argv[i], "--marker") == 0 && i + 1 < argc) {
      hidden_marker = argv[++i];
    } else {
      fprintf(stderr, "usage: %s [--expect-app|--expect-daemon] [--map-file path] [--marker str]\n",
              argv[0]);
      return 2;
    }
  }

  bool actual_app = ((getuid() % 100000U) >= 10000U);
  if (forced_mode && actual_app != expected_app) {
    fprintf(stderr, "FAIL: uid=%u app=%d expected_app=%d\n", (unsigned)getuid(), actual_app,
            expected_app);
    return 1;
  }

  size_t pg = (size_t)sysconf(_SC_PAGESIZE);

  // Create a dirty anonymous r-xp page to verify smaps Private_Dirty folding for app UIDs.
  void* dirty_exec = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dirty_exec == MAP_FAILED) {
    perror("mmap dirty_exec");
    return 1;
  }
  memset(dirty_exec, 0xcc, pg);
  if (mprotect(dirty_exec, pg, PROT_READ | PROT_EXEC) != 0) {
    perror("mprotect dirty_exec");
    return 1;
  }

  // Create a synthetic memfd mapping named "xposed_smoke" to verify memfd VMA hiding.
  int mfd = (int)syscall(__NR_memfd_create, "xposed_smoke", 0);
  void* mfd_map = MAP_FAILED;
  if (mfd >= 0) {
    if (ftruncate(mfd, (off_t)pg) == 0) {
      mfd_map = mmap(NULL, pg, PROT_READ, MAP_SHARED, mfd, 0);
      if (mfd_map != MAP_FAILED) {
        volatile char touch = *(volatile char*)mfd_map;
        (void)touch;
      }
    }
    close(mfd);
  }

  void* extra_map = MAP_FAILED;
  if (map_file) {
    int ffd = open(map_file, O_RDONLY);
    if (ffd < 0) {
      perror("open map_file");
      return 1;
    }
    extra_map = mmap(NULL, pg, PROT_READ | PROT_EXEC, MAP_PRIVATE, ffd, 0);
    close(ffd);
    if (extra_map == MAP_FAILED) {
      perror("mmap map_file");
      return 1;
    }
  }

  int fail = 0;
  for (int raw = 0; raw <= 1; raw++) {
    fail |= check_proc_maps_metadata(raw != 0);
    fail |= check_maps_hidden(raw != 0, expected_app, hidden_marker);
    fail |= check_smaps_stream(raw != 0, expected_app, (uintptr_t)dirty_exec, hidden_marker);
    fail |= check_mount_stream("/proc/self/mounts", raw != 0, expected_app, 0);
    fail |= check_mount_stream("/proc/self/mountinfo", raw != 0, expected_app, 1);
    fail |= check_mount_stream("/proc/self/mountstats", raw != 0, expected_app, 2);
    fail |= check_kernel_policy_and_adb_hide(raw != 0, expected_app);
  }
  fail |= check_statfs_paths(expected_app);

  if (extra_map != MAP_FAILED) munmap(extra_map, pg);
  if (mfd_map != MAP_FAILED) munmap(mfd_map, pg);
  munmap(dirty_exec, pg);

  if (!fail) {
    printf("PASS: yasvara_vfs_probe uid=%u mode=%s\n", (unsigned)getuid(),
           expected_app ? "app" : "daemon");
  }
  return fail ? 1 : 0;
}
