// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

// Complete C++ QTI SDE + Generic KMS Triple-Buffered Non-Blocking Atomic DRM
// backend & `fastbootd` handoff shim for `Pulih` Recovery (`SPEC-0051` §5.3).
//
// Grounded directly in verified `onyx` QTI SDE (`msm_drm`) behavior from
// `graphics_drm_qti.cpp` & live `recovery.log`:
// - Waits up to 4s for `/dev/dri/card0` + DSI connector on early boot
// - Prioritizes `DRM_MODE_CONNECTOR_DSI` / `eDP` / `LVDS`
// - Resolves CRTC via `conn->encoder_id` or `encoder->possible_crtcs` fallback
// - Enables `UNIVERSAL_PLANES` + `ATOMIC` in QTI SDE's expected order
// - Allocates 3 `DRM_FORMAT_XBGR8888` dumb buffers (`1280x2772`, 120/90/60 Hz)
// - Issues `DRM_MODE_ATOMIC_ALLOW_MODESET` ONLY ONCE on init/refresh/unblank,
//   then `DRM_MODE_ATOMIC_NONBLOCK` on steady-state frames (with sync fallback)
// - Pure C `calloc`/`free` (zero `libc++` dependency)

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <arpa/inet.h>
#include <dirent.h>
#include <drm_fourcc.h>
#include <linux/dm-ioctl.h>
#include <linux/input.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <xf86drm.h>
#include <xf86drmMode.h>
#endif

extern "C" {

struct PulihDrmInfo {
    void* handle;
    int fd;
    uint32_t width;
    uint32_t height;
    uint32_t stride_px;
    uint32_t refresh_hz;
    uint32_t num_lms;
};

#ifdef __ANDROID__

static constexpr int kSwapchainCount = 3;
static constexpr int kMaxPlanes = 4;

static void drm_log(const char* fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;

    int lfd = open("/tmp/pulih_drm.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (lfd >= 0) {
        (void)write(lfd, buf, static_cast<size_t>(n));
        close(lfd);
    }
    int kfd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (kfd >= 0) {
        (void)write(kfd, buf, static_cast<size_t>(n));
        close(kfd);
    }
}

struct DumbBuf {
    uint32_t handle;
    uint32_t fb_id;
    uint32_t pitch;
    uint64_t size;
    uint32_t* map;
};

struct DrmCtx {
    int fd;
    uint32_t conn_id;
    uint32_t crtc_id;
    uint32_t crtc_index;
    uint32_t mode_blob_id;
    drmModeConnector* conn;
    drmModeModeInfo mode;
    uint32_t plane_ids[kMaxPlanes];
    uint32_t num_lms;
    DumbBuf bufs[kSwapchainCount];
    int back_idx;
    bool modeset_done;
    bool blanked;
};

static uint32_t find_obj_prop(int fd, uint32_t obj_id, uint32_t obj_type, const char* name) {
    drmModeObjectProperties* props = drmModeObjectGetProperties(fd, obj_id, obj_type);
    if (!props) return 0;
    uint32_t found = 0;
    for (uint32_t i = 0; i < props->count_props; ++i) {
        drmModePropertyRes* p = drmModeGetProperty(fd, props->props[i]);
        if (!p) continue;
        if (strcmp(p->name, name) == 0) {
            found = p->prop_id;
            drmModeFreeProperty(p);
            break;
        }
        drmModeFreeProperty(p);
    }
    drmModeFreeObjectProperties(props);
    return found;
}

static uint32_t detect_sde_lms(int fd, uint32_t conn_id) {
    drmModeObjectProperties* props =
            drmModeObjectGetProperties(fd, conn_id, DRM_MODE_OBJECT_CONNECTOR);
    if (!props) return 1;
    uint32_t lms = 1;
    for (uint32_t i = 0; i < props->count_props; ++i) {
        drmModePropertyRes* p = drmModeGetProperty(fd, props->props[i]);
        if (!p) continue;
        if (strcmp(p->name, "mode_properties") == 0 && (p->flags & DRM_MODE_PROP_BLOB)) {
            drmModePropertyBlobRes* blob = drmModeGetPropertyBlob(fd, props->prop_values[i]);
            if (blob && blob->data && blob->length > 0) {
                const char* txt = static_cast<const char*>(blob->data);
                if (strstr(txt, "topology=sde_dualpipe")) {
                    lms = 2;
                } else if (strstr(txt, "topology=sde_quadpipe")) {
                    lms = 4;
                }
            }
            if (blob) drmModeFreePropertyBlob(blob);
            drmModeFreeProperty(p);
            break;
        }
        drmModeFreeProperty(p);
    }
    drmModeFreeObjectProperties(props);
    return lms;
}

static drmModeConnector* find_preferred_connector(int fd, drmModeRes* res) {
    static const uint32_t kPriority[] = {
        DRM_MODE_CONNECTOR_DSI,
        DRM_MODE_CONNECTOR_eDP,
        DRM_MODE_CONNECTOR_LVDS,
    };
    for (uint32_t want : kPriority) {
        for (int i = 0; i < res->count_connectors; ++i) {
            drmModeConnector* c = drmModeGetConnector(fd, res->connectors[i]);
            if (!c) continue;
            if (c->connector_type == want && c->connection == DRM_MODE_CONNECTED &&
                c->count_modes > 0) {
                return c;
            }
            drmModeFreeConnector(c);
        }
    }
    for (int i = 0; i < res->count_connectors; ++i) {
        drmModeConnector* c = drmModeGetConnector(fd, res->connectors[i]);
        if (!c) continue;
        if (c->connection == DRM_MODE_CONNECTED && c->count_modes > 0) {
            return c;
        }
        drmModeFreeConnector(c);
    }
    return nullptr;
}

static bool find_crtc(int fd, drmModeRes* res, drmModeConnector* conn, uint32_t* out_id,
                      uint32_t* out_idx) {
    if (conn->encoder_id) {
        if (drmModeEncoder* enc = drmModeGetEncoder(fd, conn->encoder_id)) {
            if (enc->crtc_id) {
                for (int j = 0; j < res->count_crtcs; ++j) {
                    if (res->crtcs[j] == enc->crtc_id) {
                        *out_id = res->crtcs[j];
                        *out_idx = static_cast<uint32_t>(j);
                        drmModeFreeEncoder(enc);
                        return true;
                    }
                }
            }
            drmModeFreeEncoder(enc);
        }
    }
    for (int i = 0; i < conn->count_encoders; ++i) {
        drmModeEncoder* enc = drmModeGetEncoder(fd, conn->encoders[i]);
        if (!enc) continue;
        for (int j = 0; j < res->count_crtcs; ++j) {
            if (enc->possible_crtcs & (1u << j)) {
                *out_id = res->crtcs[j];
                *out_idx = static_cast<uint32_t>(j);
                drmModeFreeEncoder(enc);
                return true;
            }
        }
        drmModeFreeEncoder(enc);
    }
    if (res->count_crtcs > 0) {
        *out_id = res->crtcs[0];
        *out_idx = 0;
        return true;
    }
    return false;
}

static bool create_dumb_buf(int fd, uint32_t w, uint32_t h, DumbBuf* out) {
    drm_mode_create_dumb creq = {};
    creq.width = w;
    creq.height = h;
    creq.bpp = 32;
    if (drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &creq) < 0) return false;

    uint32_t handles[4] = {creq.handle, 0, 0, 0};
    uint32_t pitches[4] = {creq.pitch, 0, 0, 0};
    uint32_t offsets[4] = {0, 0, 0, 0};
    if (drmModeAddFB2(fd, w, h, DRM_FORMAT_XBGR8888, handles, pitches, offsets, &out->fb_id, 0) !=
        0) {
        drm_mode_destroy_dumb dreq = {creq.handle};
        drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &dreq);
        return false;
    }

    drm_mode_map_dumb mreq = {};
    mreq.handle = creq.handle;
    if (drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &mreq) < 0) {
        drmModeRmFB(fd, out->fb_id);
        drm_mode_destroy_dumb dreq = {creq.handle};
        drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &dreq);
        return false;
    }

    void* ptr = mmap(nullptr, creq.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mreq.offset);
    if (ptr == MAP_FAILED) {
        drmModeRmFB(fd, out->fb_id);
        drm_mode_destroy_dumb dreq = {creq.handle};
        drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &dreq);
        return false;
    }

    memset(ptr, 0, creq.size);
    out->handle = creq.handle;
    out->pitch = creq.pitch;
    out->size = creq.size;
    out->map = static_cast<uint32_t*>(ptr);
    return true;
}

static void destroy_dumb_buf(int fd, DumbBuf* b) {
    if (b->map) {
        munmap(b->map, b->size);
        b->map = nullptr;
    }
    if (b->fb_id) {
        drmModeRmFB(fd, b->fb_id);
        b->fb_id = 0;
    }
    if (b->handle) {
        drm_mode_destroy_dumb dreq = {b->handle};
        drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &dreq);
        b->handle = 0;
    }
}

static int pick_mode_index(const drmModeConnector* conn, uint32_t target_hz) {
    int best = 0;
    int best_diff = 100000;
    for (int i = 0; i < conn->count_modes; ++i) {
        int hz = static_cast<int>(conn->modes[i].vrefresh);
        int diff = abs(hz - static_cast<int>(target_hz));
        if (diff < best_diff) {
            best_diff = diff;
            best = i;
        }
    }
    return best;
}

static void add_atomic(drmModeAtomicReq* req, int fd, uint32_t obj_id, uint32_t obj_type,
                       const char* prop, uint64_t val) {
    uint32_t pid = find_obj_prop(fd, obj_id, obj_type, prop);
    if (pid) drmModeAtomicAddProperty(req, obj_id, pid, val);
}

static int try_drm_init_once(uint32_t target_hz, PulihDrmInfo* out) {
    const char* nodes[] = {"/dev/dri/card0", "/dev/dri/card1"};
    for (const char* node : nodes) {
        int fd = open(node, O_RDWR | O_CLOEXEC);
        if (fd < 0) continue;

        uint64_t dumb_cap = 0;
        if (drmGetCap(fd, DRM_CAP_DUMB_BUFFER, &dumb_cap) != 0 || dumb_cap == 0) {
            close(fd);
            continue;
        }

        drmModeRes* res = drmModeGetResources(fd);
        if (!res) {
            close(fd);
            continue;
        }

        drmModeConnector* conn = find_preferred_connector(fd, res);
        if (!conn || res->count_crtcs <= 0) {
            if (conn) drmModeFreeConnector(conn);
            drmModeFreeResources(res);
            close(fd);
            continue;
        }

        uint32_t crtc_id = 0, crtc_index = 0;
        if (!find_crtc(fd, res, conn, &crtc_id, &crtc_index)) {
            drmModeFreeConnector(conn);
            drmModeFreeResources(res);
            close(fd);
            continue;
        }

        drmModeFreeResources(res);

        // Exact QTI SDE order (matches graphics_drm_qti.cpp:816-870)
        drmSetClientCap(fd, DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1);
        drmSetClientCap(fd, DRM_CLIENT_CAP_ATOMIC, 1);

        auto* ctx = static_cast<DrmCtx*>(calloc(1, sizeof(DrmCtx)));
        if (!ctx) {
            drmModeFreeConnector(conn);
            close(fd);
            return -ENOMEM;
        }
        ctx->fd = fd;
        ctx->conn = conn;
        ctx->conn_id = conn->connector_id;
        ctx->crtc_id = crtc_id;
        ctx->crtc_index = crtc_index;

        int mode_idx = pick_mode_index(conn, target_hz ? target_hz : 120);
        ctx->mode = conn->modes[mode_idx];
        ctx->num_lms = detect_sde_lms(fd, ctx->conn_id);
        if (ctx->num_lms < 1 || ctx->num_lms > kMaxPlanes) ctx->num_lms = 1;

        drmModePlaneRes* pres = drmModeGetPlaneResources(fd);
        if (!pres || pres->count_planes < ctx->num_lms) {
            drm_log("pulih_drm: no planes on %s (count=%u, need=%u)\n", node,
                    pres ? pres->count_planes : 0, ctx->num_lms);
            if (pres) drmModeFreePlaneResources(pres);
            drmModeFreeConnector(conn);
            close(fd);
            free(ctx);
            continue;
        }
        for (uint32_t i = 0; i < ctx->num_lms; ++i) {
            ctx->plane_ids[i] = pres->planes[i];
        }
        drmModeFreePlaneResources(pres);

        bool ok = true;
        for (int i = 0; i < kSwapchainCount; ++i) {
            if (!create_dumb_buf(fd, ctx->mode.hdisplay, ctx->mode.vdisplay, &ctx->bufs[i])) {
                drm_log("pulih_drm: create_dumb_buf %d failed (%dx%d)\n", i, ctx->mode.hdisplay,
                        ctx->mode.vdisplay);
                ok = false;
                break;
            }
        }
        if (!ok) {
            for (int i = 0; i < kSwapchainCount; ++i) destroy_dumb_buf(fd, &ctx->bufs[i]);
            drmModeFreeConnector(conn);
            close(fd);
            free(ctx);
            continue;
        }

        drmModeCreatePropertyBlob(fd, &ctx->mode, sizeof(ctx->mode), &ctx->mode_blob_id);

        out->handle = ctx;
        out->fd = fd;
        out->width = ctx->mode.hdisplay;
        out->height = ctx->mode.vdisplay;
        out->stride_px = ctx->bufs[0].pitch / 4;
        out->refresh_hz = ctx->mode.vrefresh ? ctx->mode.vrefresh : 60;
        out->num_lms = ctx->num_lms;
        drm_log("pulih_drm: READY %s conn=%u(type=%u) crtc=%u %ux%u@%uHz lms=%u plane0=%u\n", node,
                ctx->conn_id, conn->connector_type, ctx->crtc_id, out->width, out->height,
                out->refresh_hz, out->num_lms, ctx->plane_ids[0]);
        return 0;
    }
    return -ENODEV;
}

int pulih_drm_init(uint32_t target_hz, PulihDrmInfo* out) {
    if (!out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    out->fd = -1;
    // Wait up to 4s for msm_drm /dev/dri/card0 + DSI panel probe on early recovery boot
    for (int attempt = 0; attempt < 40; ++attempt) {
        int rc = try_drm_init_once(target_hz, out);
        if (rc == 0) return 0;
        usleep(100 * 1000);
    }
    drm_log("pulih_drm: gave up after 4s waiting for DRM connector\n");
    return -ENODEV;
}

uint32_t* pulih_drm_backbuffer(void* handle) {
    if (!handle) return nullptr;
    auto* ctx = static_cast<DrmCtx*>(handle);
    return ctx->bufs[ctx->back_idx].map;
}

int pulih_drm_flip(void* handle) {
    if (!handle) return -EINVAL;
    auto* ctx = static_cast<DrmCtx*>(handle);
    if (ctx->blanked) return 0;

    drmModeAtomicReq* req = drmModeAtomicAlloc();
    if (!req) return -ENOMEM;

    const DumbBuf& buf = ctx->bufs[ctx->back_idx];
    uint32_t flags = DRM_MODE_ATOMIC_NONBLOCK;

    if (!ctx->modeset_done) {
        flags = DRM_MODE_ATOMIC_ALLOW_MODESET;
        add_atomic(req, ctx->fd, ctx->conn_id, DRM_MODE_OBJECT_CONNECTOR, "CRTC_ID", ctx->crtc_id);
        add_atomic(req, ctx->fd, ctx->crtc_id, DRM_MODE_OBJECT_CRTC, "MODE_ID", ctx->mode_blob_id);
        add_atomic(req, ctx->fd, ctx->crtc_id, DRM_MODE_OBJECT_CRTC, "ACTIVE", 1);
    } else {
        add_atomic(req, ctx->fd, ctx->conn_id, DRM_MODE_OBJECT_CONNECTOR, "CRTC_ID", ctx->crtc_id);
    }

    uint32_t w = ctx->mode.hdisplay;
    uint32_t h = ctx->mode.vdisplay;
    uint32_t slice_w = w / ctx->num_lms;
    for (uint32_t i = 0; i < ctx->num_lms; ++i) {
        uint32_t pid = ctx->plane_ids[i];
        uint32_t x = slice_w * i;
        add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "FB_ID", buf.fb_id);
        if (!ctx->modeset_done) {
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "CRTC_ID", ctx->crtc_id);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "SRC_X",
                       static_cast<uint64_t>(x) << 16);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "SRC_Y", 0);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "SRC_W",
                       static_cast<uint64_t>(slice_w) << 16);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "SRC_H",
                       static_cast<uint64_t>(h) << 16);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "CRTC_X", x);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "CRTC_Y", 0);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "CRTC_W", slice_w);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "CRTC_H", h);
            add_atomic(req, ctx->fd, pid, DRM_MODE_OBJECT_PLANE, "zpos", 0);
        }
    }

    int ret = drmModeAtomicCommit(ctx->fd, req, flags, nullptr);
    if (ret != 0 && (flags & DRM_MODE_ATOMIC_NONBLOCK)) {
        // On -EBUSY (previous VSYNC flip still pending), wait briefly and retry
        // cleanly — NEVER force ALLOW_MODESET during normal 120Hz frame flips!
        if (errno == EBUSY) {
            usleep(1500);
            ret = drmModeAtomicCommit(ctx->fd, req, DRM_MODE_ATOMIC_NONBLOCK, nullptr);
        }
        if (ret != 0) {
            ret = drmModeAtomicCommit(ctx->fd, req, 0, nullptr);
        }
    }
    drmModeAtomicFree(req);
    if (ret == 0) {
        if (!ctx->modeset_done) {
            drm_log("pulih_drm: first atomic modeset commit SUCCEEDED (fb=%u)\n", buf.fb_id);
        }
        ctx->modeset_done = true;
        ctx->back_idx = (ctx->back_idx + 1) % kSwapchainCount;
    } else {
        drm_log("pulih_drm: atomic commit FAILED ret=%d errno=%d\n", ret, errno);
    }
    return ret;
}

int pulih_drm_set_refresh(void* handle, uint32_t target_hz) {
    if (!handle) return -EINVAL;
    auto* ctx = static_cast<DrmCtx*>(handle);
    if (!ctx->conn || ctx->conn->count_modes <= 0) return -EINVAL;

    int idx = pick_mode_index(ctx->conn, target_hz);
    const drmModeModeInfo& next = ctx->conn->modes[idx];
    if (next.hdisplay != ctx->mode.hdisplay || next.vdisplay != ctx->mode.vdisplay) {
        return -EINVAL;
    }
    if (ctx->mode_blob_id) {
        drmModeDestroyPropertyBlob(ctx->fd, ctx->mode_blob_id);
        ctx->mode_blob_id = 0;
    }
    ctx->mode = next;
    drmModeCreatePropertyBlob(ctx->fd, &ctx->mode, sizeof(ctx->mode), &ctx->mode_blob_id);
    ctx->modeset_done = false;
    return static_cast<int>(ctx->mode.vrefresh);
}

int pulih_drm_blank(void* handle, int blank) {
    if (!handle) return -EINVAL;
    auto* ctx = static_cast<DrmCtx*>(handle);
    if (ctx->blanked == (blank != 0)) return 0;

    if (!blank) {
        // Unblank: clear blank flag and force next pulih_drm_flip() to execute
        // the complete QTI SDE atomic SetupPipeline (CRTC_ID + MODE_ID + ACTIVE=1 + planes)!
        ctx->blanked = false;
        ctx->modeset_done = false;
        drm_log("pulih_drm: unblank requested -> full SetupPipeline armed on next flip\n");
        return 0;
    }

    // Blank: execute full QTI SDE TeardownPipeline (matches graphics_drm_qti.cpp:342-370)
    drmModeAtomicReq* req = drmModeAtomicAlloc();
    if (!req) return -ENOMEM;
    add_atomic(req, ctx->fd, ctx->conn_id, DRM_MODE_OBJECT_CONNECTOR, "CRTC_ID", 0);
    add_atomic(req, ctx->fd, ctx->crtc_id, DRM_MODE_OBJECT_CRTC, "MODE_ID", 0);
    add_atomic(req, ctx->fd, ctx->crtc_id, DRM_MODE_OBJECT_CRTC, "ACTIVE", 0);
    for (uint32_t i = 0; i < ctx->num_lms; ++i) {
        add_atomic(req, ctx->fd, ctx->plane_ids[i], DRM_MODE_OBJECT_PLANE, "CRTC_ID", 0);
        add_atomic(req, ctx->fd, ctx->plane_ids[i], DRM_MODE_OBJECT_PLANE, "FB_ID", 0);
    }
    int ret = drmModeAtomicCommit(ctx->fd, req, DRM_MODE_ATOMIC_ALLOW_MODESET, nullptr);
    drmModeAtomicFree(req);
    ctx->blanked = true;
    ctx->modeset_done = false;
    drm_log("pulih_drm: blank TeardownPipeline ret=%d\n", ret);
    return ret;
}

int pulih_drm_drop_master(void* handle) {
    if (!handle) return -EINVAL;
    auto* ctx = static_cast<DrmCtx*>(handle);
    return drmDropMaster(ctx->fd);
}

int pulih_drm_set_master(void* handle) {
    if (!handle) return -EINVAL;
    auto* ctx = static_cast<DrmCtx*>(handle);
    ctx->modeset_done = false;
    return drmSetMaster(ctx->fd);
}

void pulih_drm_destroy(void* handle) {
    if (!handle) return;
    auto* ctx = static_cast<DrmCtx*>(handle);
    for (int i = 0; i < kSwapchainCount; ++i) destroy_dumb_buf(ctx->fd, &ctx->bufs[i]);
    if (ctx->mode_blob_id) drmModeDestroyPropertyBlob(ctx->fd, ctx->mode_blob_id);
    if (ctx->conn) drmModeFreeConnector(ctx->conn);
    if (ctx->fd >= 0) close(ctx->fd);
    free(ctx);
}

#else

int pulih_drm_init(uint32_t, PulihDrmInfo* out) {
    if (out) {
        memset(out, 0, sizeof(*out));
        out->fd = -1;
    }
    return -ENOSYS;
}
uint32_t* pulih_drm_backbuffer(void*) { return nullptr; }
int pulih_drm_flip(void*) { return -ENOSYS; }
int pulih_drm_set_refresh(void*, uint32_t) { return -ENOSYS; }
int pulih_drm_blank(void*, int) { return -ENOSYS; }
int pulih_drm_drop_master(void*) { return -ENOSYS; }
int pulih_drm_set_master(void*) { return -ENOSYS; }
void pulih_drm_destroy(void*) {}

#endif

int pulih_exec_fastbootd(void) {
    char* const argv[] = {const_cast<char*>("/system/bin/fastbootd"), nullptr};
    execv("/system/bin/fastbootd", argv);
    return -errno;
}

// ====================================================== Per-FD Linux evdev (<linux/input.h>)

struct PulihRawEvent {
    uint16_t type;
    uint16_t code;
    int32_t value;
    int32_t min_x;
    int32_t max_x;
    int32_t min_y;
    int32_t max_y;
    uint8_t has_abs;
};

#ifdef __ANDROID__

static constexpr int kMaxEvdevFds = 32;

struct EvdevEntry {
    int fd;
    char dev_name[32];
    char friendly[64];
    int32_t min_x;
    int32_t max_x;
    int32_t min_y;
    int32_t max_y;
    bool has_abs;
};

struct InputCtx {
    EvdevEntry entries[kMaxEvdevFds];
    int count;
};

static bool evdev_already_open(const InputCtx* ctx, const char* name) {
    for (int i = 0; i < ctx->count; ++i) {
        if (strcmp(ctx->entries[i].dev_name, name) == 0) return true;
    }
    return false;
}

int pulih_input_rescan(void* handle) {
    if (!handle) return 0;
    auto* ctx = static_cast<InputCtx*>(handle);
    DIR* dir = opendir("/dev/input");
    if (!dir) return ctx->count;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr && ctx->count < kMaxEvdevFds) {
        if (strncmp(ent->d_name, "event", 5) != 0) continue;
        if (evdev_already_open(ctx, ent->d_name)) continue;

        char path[64];
        snprintf(path, sizeof(path), "/dev/input/%s", ent->d_name);
        int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;

        EvdevEntry& e = ctx->entries[ctx->count++];
        memset(&e, 0, sizeof(e));
        e.fd = fd;
        strncpy(e.dev_name, ent->d_name, sizeof(e.dev_name) - 1);
        if (ioctl(fd, EVIOCGNAME(sizeof(e.friendly) - 1), e.friendly) < 0) {
            strncpy(e.friendly, ent->d_name, sizeof(e.friendly) - 1);
        }

        struct input_absinfo ax = {};
        struct input_absinfo ay = {};
        if (ioctl(fd, EVIOCGABS(ABS_MT_POSITION_X), &ax) == 0 && ax.maximum > ax.minimum &&
            ioctl(fd, EVIOCGABS(ABS_MT_POSITION_Y), &ay) == 0 && ay.maximum > ay.minimum) {
            e.min_x = ax.minimum;
            e.max_x = ax.maximum;
            e.min_y = ay.minimum;
            e.max_y = ay.maximum;
            e.has_abs = true;
        } else if (ioctl(fd, EVIOCGABS(ABS_X), &ax) == 0 && ax.maximum > ax.minimum &&
                   ioctl(fd, EVIOCGABS(ABS_Y), &ay) == 0 && ay.maximum > ay.minimum) {
            e.min_x = ax.minimum;
            e.max_x = ax.maximum;
            e.min_y = ay.minimum;
            e.max_y = ay.maximum;
            e.has_abs = true;
        }
        drm_log("pulih_evdev: opened %s (%s) abs=%d x=[%d..%d] y=[%d..%d]\n", path, e.friendly,
                e.has_abs ? 1 : 0, e.min_x, e.max_x, e.min_y, e.max_y);
    }
    closedir(dir);
    return ctx->count;
}

void* pulih_input_open(void) {
    auto* ctx = static_cast<InputCtx*>(calloc(1, sizeof(InputCtx)));
    if (!ctx) return nullptr;
    pulih_input_rescan(ctx);
    return ctx;
}

int pulih_input_count(void* handle, int* out_touch_max_x, int* out_touch_max_y) {
    if (!handle) return 0;
    auto* ctx = static_cast<InputCtx*>(handle);
    if (out_touch_max_x) *out_touch_max_x = 0;
    if (out_touch_max_y) *out_touch_max_y = 0;
    for (int i = 0; i < ctx->count; ++i) {
        if (ctx->entries[i].has_abs) {
            if (out_touch_max_x) *out_touch_max_x = ctx->entries[i].max_x;
            if (out_touch_max_y) *out_touch_max_y = ctx->entries[i].max_y;
            if (strstr(ctx->entries[i].friendly, "Touch") ||
                strstr(ctx->entries[i].friendly, "touch") ||
                strstr(ctx->entries[i].friendly, "NVT")) {
                break;
            }
        }
    }
    return ctx->count;
}

int pulih_input_poll(void* handle, int timeout_ms, PulihRawEvent* out_buf, int max_events) {
    if (!handle || !out_buf || max_events <= 0) return 0;
    auto* ctx = static_cast<InputCtx*>(handle);
    if (ctx->count <= 0) {
        if (timeout_ms > 0) usleep(static_cast<useconds_t>(timeout_ms > 250 ? 250 : timeout_ms) * 1000);
        return 0;
    }

    struct pollfd pfds[kMaxEvdevFds];
    for (int i = 0; i < ctx->count; ++i) {
        pfds[i].fd = ctx->entries[i].fd;
        pfds[i].events = POLLIN;
        pfds[i].revents = 0;
    }

    int ready = poll(pfds, static_cast<nfds_t>(ctx->count), timeout_ms);
    if (ready <= 0) return 0;

    int written = 0;
    struct input_event evs[32];
    for (int i = 0; i < ctx->count && written < max_events; ++i) {
        if (!(pfds[i].revents & POLLIN)) continue;
        const EvdevEntry& e = ctx->entries[i];
        while (written < max_events) {
            ssize_t n = read(e.fd, evs, sizeof(evs));
            if (n < static_cast<ssize_t>(sizeof(struct input_event))) break;
            int cnt = static_cast<int>(n / sizeof(struct input_event));
            for (int k = 0; k < cnt && written < max_events; ++k) {
                PulihRawEvent& dst = out_buf[written++];
                dst.type = evs[k].type;
                dst.code = evs[k].code;
                dst.value = evs[k].value;
                dst.min_x = e.min_x;
                dst.max_x = e.max_x;
                dst.min_y = e.min_y;
                dst.max_y = e.max_y;
                dst.has_abs = e.has_abs ? 1 : 0;
            }
        }
    }
    return written;
}

void pulih_input_close(void* handle) {
    if (!handle) return;
    auto* ctx = static_cast<InputCtx*>(handle);
    for (int i = 0; i < ctx->count; ++i) {
        if (ctx->entries[i].fd >= 0) close(ctx->entries[i].fd);
    }
    free(ctx);
}

// ====================================================== Hardware Haptics (si_haptic / EV_FF)

static int g_haptic_fd = -1;
static int g_haptic_effect_id = -1;
static bool g_haptic_probed = false;
static bool g_haptic_has_const = false;
static bool g_haptic_has_periodic = false;
static bool g_haptic_has_rumble = false;

static bool ff_test_bit(int bit, const uint8_t* arr) {
    return (arr[bit / 8] & (1u << (bit % 8))) != 0;
}

static bool is_haptic_device_name(const char* name) {
    static const char* kNames[] = {
        "si_haptic",
        "qcom-hv-haptics",
        "qti-haptics",
        "aw-haptic-hv",
        "aw8624_haptic",
        "aw8695_haptic",
        "aw8697_haptic",
        "awinic_haptic",
        "drv260x:haptics",
        "drv2624:haptics",
        "haptic_rt",
    };
    for (const char* cand : kNames) {
        if (strcmp(name, cand) == 0) return true;
    }
    return false;
}

static int ensure_haptic_open(void) {
    if (g_haptic_fd >= 0) return g_haptic_fd;
    if (g_haptic_probed) return -1;
    g_haptic_probed = true;

    DIR* dir = opendir("/dev/input");
    if (!dir) return -1;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (strncmp(ent->d_name, "event", 5) != 0) continue;
        char path[64];
        snprintf(path, sizeof(path), "/dev/input/%s", ent->d_name);
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0) continue;

        char name[64] = {};
        if (ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name) < 0 || !is_haptic_device_name(name)) {
            close(fd);
            continue;
        }

        uint8_t ff_bits[(FF_CNT + 7) / 8] = {};
        if (ioctl(fd, EVIOCGBIT(EV_FF, sizeof(ff_bits)), ff_bits) < 0) {
            close(fd);
            continue;
        }

        bool has_const = ff_test_bit(FF_CONSTANT, ff_bits);
        bool has_periodic = ff_test_bit(FF_PERIODIC, ff_bits) && ff_test_bit(FF_CUSTOM, ff_bits);
        bool has_rumble = ff_test_bit(FF_RUMBLE, ff_bits);
        bool has_gain = ff_test_bit(FF_GAIN, ff_bits);
        if (!has_const && !has_periodic && !has_rumble) {
            close(fd);
            continue;
        }

        g_haptic_fd = fd;
        g_haptic_has_const = has_const;
        g_haptic_has_periodic = has_periodic;
        g_haptic_has_rumble = has_rumble;

        if (has_gain) {
            struct input_event gain = {};
            gain.type = EV_FF;
            gain.code = FF_GAIN;
            gain.value = 0xFFFF;
            (void)write(fd, &gain, sizeof(gain));
        }

        drm_log("pulih_haptic: READY %s (%s) const=%d periodic=%d rumble=%d gain=%d\n",
                path, name, has_const ? 1 : 0, has_periodic ? 1 : 0, has_rumble ? 1 : 0,
                has_gain ? 1 : 0);
        break;
    }
    closedir(dir);
    return g_haptic_fd;
}

int pulih_haptic_click(uint32_t duration_ms) {
    int fd = ensure_haptic_open();
    if (fd < 0) return -ENODEV;

    uint32_t ms = duration_ms < 8 ? 8 : (duration_ms > 200 ? 200 : duration_ms);

    if (g_haptic_effect_id >= 0) {
        (void)ioctl(fd, EVIOCRMFF, g_haptic_effect_id);
        g_haptic_effect_id = -1;
    }

    struct ff_effect effect = {};
    int16_t custom_data[3] = {0, 0, 0};  // RAM wave 0 = CLICK on si_haptic
    int ret = -1;

    if (g_haptic_has_const) {
        memset(&effect, 0, sizeof(effect));
        effect.type = FF_CONSTANT;
        effect.id = -1;
        effect.u.constant.level = 0x7FFF;
        effect.replay.length = static_cast<uint16_t>(ms);
        effect.replay.delay = 0;
        ret = ioctl(fd, EVIOCSFF, &effect);
    }

    if (ret < 0 && g_haptic_has_periodic) {
        memset(&effect, 0, sizeof(effect));
        effect.type = FF_PERIODIC;
        effect.id = -1;
        effect.u.periodic.waveform = FF_CUSTOM;
        effect.u.periodic.magnitude = 0x7FFF;
        effect.u.periodic.custom_data = custom_data;
        effect.u.periodic.custom_len = 3;
        effect.replay.length = static_cast<uint16_t>(ms);
        effect.replay.delay = 0;
        ret = ioctl(fd, EVIOCSFF, &effect);
    }

    if (ret < 0 && g_haptic_has_rumble) {
        memset(&effect, 0, sizeof(effect));
        effect.type = FF_RUMBLE;
        effect.id = -1;
        effect.u.rumble.strong_magnitude = 0x7FFF;
        effect.u.rumble.weak_magnitude = 0x4000;
        effect.replay.length = static_cast<uint16_t>(ms);
        effect.replay.delay = 0;
        ret = ioctl(fd, EVIOCSFF, &effect);
    }

    if (ret < 0) {
        int err = errno ? -errno : -EIO;
        drm_log("pulih_haptic: EVIOCSFF failed err=%d\n", err);
        return err;
    }

    g_haptic_effect_id = effect.id;
    struct input_event play = {};
    play.type = EV_FF;
    play.code = static_cast<uint16_t>(g_haptic_effect_id);
    play.value = 1;
    if (write(fd, &play, sizeof(play)) < 0) {
        int err = errno ? -errno : -EIO;
        drm_log("pulih_haptic: write EV_FF failed err=%d\n", err);
        return err;
    }
    return 0;
}

// ====================================================== Read-Only dm-linear Super Mapper

struct PulihDmExtent {
    uint64_t logical_sector;
    uint64_t num_sectors;
    uint64_t physical_sector;
    uint32_t target_type;  // 0 = linear, 1 = zero
};

static int open_dm_control(void) {
    int fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC);
    if (fd < 0) fd = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
    return fd;
}

static void init_dm_hdr(struct dm_ioctl* io, uint32_t data_size, const char* name) {
    memset(io, 0, sizeof(*io));
    io->version[0] = DM_VERSION_MAJOR;
    io->version[1] = 0;
    io->version[2] = 0;
    io->data_size = data_size;
    io->data_start = sizeof(struct dm_ioctl);
    if (name) {
        strncpy(io->name, name, sizeof(io->name) - 1);
    }
}

int pulih_dm_map_ro(const char* dm_name, const char* super_path,
                    const PulihDmExtent* extents, uint32_t num_extents) {
    if (!dm_name || !super_path || !extents || num_extents == 0) return -EINVAL;

    struct stat st = {};
    if (stat(super_path, &st) != 0 || !S_ISBLK(st.st_mode)) {
        return errno ? -errno : -ENODEV;
    }
    unsigned int super_maj = major(st.st_rdev);
    unsigned int super_min = minor(st.st_rdev);

    int fd = open_dm_control();
    if (fd < 0) return errno ? -errno : -ENODEV;

    struct dm_ioctl io = {};
    init_dm_hdr(&io, sizeof(io), dm_name);
    io.flags = DM_READONLY_FLAG;

    bool existed = false;
    if (ioctl(fd, DM_DEV_CREATE, &io) < 0) {
        if (errno == EBUSY) {
            existed = true;
            init_dm_hdr(&io, sizeof(io), dm_name);
            if (ioctl(fd, DM_DEV_STATUS, &io) < 0) {
                int err = errno ? -errno : -EIO;
                close(fd);
                return err;
            }
        } else {
            int err = errno ? -errno : -EIO;
            drm_log("pulih_dm: DM_DEV_CREATE %s failed err=%d\n", dm_name, err);
            close(fd);
            return err;
        }
    }

    uint64_t dm_dev = io.dev;

    if (!existed) {
        const size_t kBufSize = 65536;
        auto* buf = static_cast<uint8_t*>(calloc(1, kBufSize));
        if (!buf) {
            close(fd);
            return -ENOMEM;
        }
        auto* tbl = reinterpret_cast<struct dm_ioctl*>(buf);
        init_dm_hdr(tbl, static_cast<uint32_t>(kBufSize), dm_name);
        tbl->target_count = num_extents;
        tbl->flags = DM_READONLY_FLAG;

        size_t pos = sizeof(struct dm_ioctl);
        for (uint32_t i = 0; i < num_extents; ++i) {
            char params[64] = {};
            if (extents[i].target_type == 0) {
                snprintf(params, sizeof(params), "%u:%u %llu", super_maj, super_min,
                         static_cast<unsigned long long>(extents[i].physical_sector));
            }
            size_t plen = strlen(params) + 1;
            size_t rec_len = (sizeof(struct dm_target_spec) + plen + 7u) & ~7u;
            if (pos + rec_len > kBufSize) {
                free(buf);
                close(fd);
                return -ENOSPC;
            }
            auto* spec = reinterpret_cast<struct dm_target_spec*>(buf + pos);
            spec->sector_start = extents[i].logical_sector;
            spec->length = extents[i].num_sectors;
            spec->status = 0;
            spec->next = static_cast<uint32_t>(rec_len);
            strncpy(spec->target_type, extents[i].target_type == 0 ? "linear" : "zero",
                    sizeof(spec->target_type) - 1);
            memcpy(buf + pos + sizeof(struct dm_target_spec), params, plen);
            pos += rec_len;
        }

        if (ioctl(fd, DM_TABLE_LOAD, tbl) < 0) {
            int err = errno ? -errno : -EIO;
            drm_log("pulih_dm: DM_TABLE_LOAD %s failed err=%d\n", dm_name, err);
            free(buf);
            init_dm_hdr(&io, sizeof(io), dm_name);
            (void)ioctl(fd, DM_DEV_REMOVE, &io);
            close(fd);
            return err;
        }
        free(buf);

        // Resume activates the newly loaded inactive table
        init_dm_hdr(&io, sizeof(io), dm_name);
        io.flags = DM_READONLY_FLAG;
        if (ioctl(fd, DM_DEV_SUSPEND, &io) < 0) {
            int err = errno ? -errno : -EIO;
            drm_log("pulih_dm: DM_DEV_SUSPEND(resume) %s failed err=%d\n", dm_name, err);
            init_dm_hdr(&io, sizeof(io), dm_name);
            (void)ioctl(fd, DM_DEV_REMOVE, &io);
            close(fd);
            return err;
        }
        dm_dev = io.dev;
    }

    close(fd);

    (void)mkdir("/dev/block", 0755);
    (void)mkdir("/dev/block/mapper", 0755);
    char node_path[192];
    snprintf(node_path, sizeof(node_path), "/dev/block/mapper/%s", dm_name);
    (void)unlink(node_path);
    dev_t rdev = makedev(static_cast<unsigned int>((dm_dev >> 8) & 0xfffu) |
                             static_cast<unsigned int>((dm_dev >> 32) & ~0xfffu),
                         static_cast<unsigned int>(dm_dev & 0xffu) |
                             static_cast<unsigned int>((dm_dev >> 12) & ~0xffu));
    if (mknod(node_path, S_IFBLK | 0600, rdev) != 0) {
        int err = errno ? -errno : -EIO;
        drm_log("pulih_dm: mknod %s failed err=%d\n", node_path, err);
        return err;
    }
    drm_log("pulih_dm: READY %s (extents=%u dev=%u:%u)\n", node_path, num_extents,
            major(rdev), minor(rdev));
    return 0;
}

int pulih_dm_remove(const char* dm_name) {
    if (!dm_name) return -EINVAL;
    int fd = open_dm_control();
    if (fd < 0) return -ENODEV;
    struct dm_ioctl io = {};
    init_dm_hdr(&io, sizeof(io), dm_name);
    int ret = ioctl(fd, DM_DEV_REMOVE, &io) < 0 ? (errno ? -errno : -EIO) : 0;
    close(fd);
    char node_path[192];
    snprintf(node_path, sizeof(node_path), "/dev/block/mapper/%s", dm_name);
    (void)unlink(node_path);
    return ret;
}

// ====================================================== Native BoringSSL HTTPS + UDP DNS Fetch

static bool resolve_ipv4_dns_udp(const char* host, const char* dns_ip, struct in_addr* out) {
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return false;
    struct timeval tv = {2, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    uint8_t pkt[512] = {};
    pkt[0] = 0x59; pkt[1] = 0x56;  // TXID "YV"
    pkt[2] = 0x01; pkt[3] = 0x00;  // Standard recursive query
    pkt[5] = 0x01;                 // QDCOUNT = 1
    size_t pos = 12;
    const char* p = host;
    while (*p && pos < 240) {
        const char* dot = strchr(p, '.');
        size_t len = dot ? static_cast<size_t>(dot - p) : strlen(p);
        if (len == 0 || len > 63 || pos + 1 + len >= 245) {
            close(s);
            return false;
        }
        pkt[pos++] = static_cast<uint8_t>(len);
        memcpy(pkt + pos, p, len);
        pos += len;
        if (!dot) break;
        p = dot + 1;
    }
    pkt[pos++] = 0;  // root label
    pkt[pos++] = 0; pkt[pos++] = 1;  // QTYPE = A
    pkt[pos++] = 0; pkt[pos++] = 1;  // QCLASS = IN

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    if (inet_pton(AF_INET, dns_ip, &dst.sin_addr) != 1) {
        close(s);
        return false;
    }
    if (sendto(s, pkt, pos, 0, reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)) < 0) {
        close(s);
        return false;
    }

    uint8_t resp[512] = {};
    ssize_t n = recv(s, resp, sizeof(resp), 0);
    close(s);
    if (n < 12) return false;
    uint16_t qd = static_cast<uint16_t>((resp[4] << 8) | resp[5]);
    uint16_t an = static_cast<uint16_t>((resp[6] << 8) | resp[7]);
    if (an == 0) return false;

    size_t off = 12;
    for (uint16_t q = 0; q < qd && off < static_cast<size_t>(n); ++q) {
        while (off < static_cast<size_t>(n)) {
            uint8_t l = resp[off++];
            if (l == 0) break;
            if ((l & 0xC0) == 0xC0) { off++; break; }
            off += l;
        }
        off += 4;
    }
    for (uint16_t a = 0; a < an && off + 12 <= static_cast<size_t>(n); ++a) {
        if ((resp[off] & 0xC0) == 0xC0) {
            off += 2;
        } else {
            while (off < static_cast<size_t>(n)) {
                uint8_t l = resp[off++];
                if (l == 0) break;
                off += l;
            }
        }
        if (off + 10 > static_cast<size_t>(n)) break;
        uint16_t rtype = static_cast<uint16_t>((resp[off] << 8) | resp[off + 1]);
        uint16_t rdlen = static_cast<uint16_t>((resp[off + 8] << 8) | resp[off + 9]);
        off += 10;
        if (rtype == 1 && rdlen == 4 && off + 4 <= static_cast<size_t>(n)) {
            memcpy(&out->s_addr, resp + off, 4);
            return true;
        }
        off += rdlen;
    }
    return false;
}

static bool parse_url_parts(const char* url, bool* out_https, char* host, size_t host_cap,
                            uint16_t* out_port, char* path, size_t path_cap) {
    const char* rest = nullptr;
    if (strncmp(url, "https://", 8) == 0) {
        *out_https = true;
        *out_port = 443;
        rest = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        *out_https = false;
        *out_port = 80;
        rest = url + 7;
    } else {
        return false;
    }
    const char* slash = strchr(rest, '/');
    size_t auth_len = slash ? static_cast<size_t>(slash - rest) : strlen(rest);
    if (auth_len == 0 || auth_len >= host_cap) return false;

    const char* colon = nullptr;
    for (size_t i = 0; i < auth_len; ++i) {
        if (rest[i] == ':') {
            colon = rest + i;
            break;
        }
    }
    if (colon) {
        size_t hlen = static_cast<size_t>(colon - rest);
        if (hlen == 0 || hlen >= host_cap) return false;
        memcpy(host, rest, hlen);
        host[hlen] = '\0';
        int p = atoi(colon + 1);
        if (p > 0 && p <= 65535) *out_port = static_cast<uint16_t>(p);
    } else {
        memcpy(host, rest, auth_len);
        host[auth_len] = '\0';
    }
    if (slash) {
        strncpy(path, slash, path_cap - 1);
        path[path_cap - 1] = '\0';
    } else {
        strncpy(path, "/", path_cap - 1);
    }
    return true;
}

static size_t decode_chunked_inplace(char* data, size_t len) {
    size_t r = 0, w = 0;
    while (r < len) {
        size_t line_end = r;
        while (line_end + 1 < len && !(data[line_end] == '\r' && data[line_end + 1] == '\n')) {
            line_end++;
        }
        if (line_end + 1 >= len) break;
        char hexbuf[24] = {};
        size_t hlen = line_end - r;
        if (hlen >= sizeof(hexbuf)) hlen = sizeof(hexbuf) - 1;
        memcpy(hexbuf, data + r, hlen);
        char* semi = strchr(hexbuf, ';');
        if (semi) *semi = '\0';
        unsigned long chunk_sz = strtoul(hexbuf, nullptr, 16);
        r = line_end + 2;
        if (chunk_sz == 0) break;
        if (r + chunk_sz > len) chunk_sz = len - r;
        memmove(data + w, data + r, chunk_sz);
        w += chunk_sz;
        r += chunk_sz;
        if (r + 1 < len && data[r] == '\r' && data[r + 1] == '\n') r += 2;
    }
    return w;
}

int pulih_http_fetch(const char* url, char* out_buf, size_t out_cap, size_t* out_len,
                     char* err_buf, size_t err_cap) {
    if (!url || !out_buf || out_cap < 256 || !out_len) return -EINVAL;
    *out_len = 0;
    if (err_buf && err_cap > 0) err_buf[0] = '\0';

    char cur_url[1024];
    strncpy(cur_url, url, sizeof(cur_url) - 1);
    cur_url[sizeof(cur_url) - 1] = '\0';

    for (int hop = 0; hop < 5; ++hop) {
        bool is_https = false;
        uint16_t port = 80;
        char host[256] = {};
        char path[768] = {};
        if (!parse_url_parts(cur_url, &is_https, host, sizeof(host), &port, path, sizeof(path))) {
            if (err_buf) snprintf(err_buf, err_cap, "Invalid URL");
            return -EINVAL;
        }

        struct in_addr ip4 = {};
        bool resolved = (inet_pton(AF_INET, host, &ip4) == 1);
        if (!resolved) {
            struct addrinfo hints = {};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            struct addrinfo* res = nullptr;
            if (getaddrinfo(host, nullptr, &hints, &res) == 0 && res) {
                ip4 = reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr;
                freeaddrinfo(res);
                resolved = true;
            }
        }
        if (!resolved) resolved = resolve_ipv4_dns_udp(host, "1.1.1.1", &ip4);
        if (!resolved) resolved = resolve_ipv4_dns_udp(host, "8.8.8.8", &ip4);
        if (!resolved) {
            if (err_buf) snprintf(err_buf, err_cap, "DNS failed for %s (connect Wi-Fi 7 first)", host);
            return -EHOSTUNREACH;
        }

        int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock < 0) return -errno;
        struct timeval tv = {8, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr = ip4;
        if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            int err = errno ? -errno : -ECONNREFUSED;
            close(sock);
            if (err_buf) snprintf(err_buf, err_cap, "Connect %s:%u failed (errno=%d)", host, port, -err);
            return err;
        }

        SSL_CTX* ssl_ctx = nullptr;
        SSL* ssl = nullptr;
        if (is_https) {
            ssl_ctx = SSL_CTX_new(TLS_client_method());
            if (!ssl_ctx) {
                close(sock);
                if (err_buf) snprintf(err_buf, err_cap, "TLS init failed");
                return -ENOMEM;
            }
            ssl = SSL_new(ssl_ctx);
            SSL_set_tlsext_host_name(ssl, host);
            SSL_set_fd(ssl, sock);
            if (SSL_connect(ssl) != 1) {
                SSL_free(ssl);
                SSL_CTX_free(ssl_ctx);
                close(sock);
                if (err_buf) snprintf(err_buf, err_cap, "TLS handshake failed with %s", host);
                return -EIO;
            }
        }

        char req[1280];
        int req_len = snprintf(
                req, sizeof(req),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0 (Linux; Android 17; POCO F7) Pulih-Jelajah/1.0\r\n"
                "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n",
                path, host);
        int sent = is_https ? SSL_write(ssl, req, req_len) : static_cast<int>(send(sock, req, req_len, 0));
        if (sent <= 0) {
            if (ssl) SSL_free(ssl);
            if (ssl_ctx) SSL_CTX_free(ssl_ctx);
            close(sock);
            if (err_buf) snprintf(err_buf, err_cap, "HTTP send failed");
            return -EIO;
        }

        size_t total = 0;
        while (total + 1 < out_cap) {
            size_t space = out_cap - 1 - total;
            if (space > 16384) space = 16384;
            int n = is_https ? SSL_read(ssl, out_buf + total, static_cast<int>(space))
                             : static_cast<int>(recv(sock, out_buf + total, space, 0));
            if (n <= 0) break;
            total += static_cast<size_t>(n);
        }
        out_buf[total] = '\0';

        if (ssl) SSL_free(ssl);
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        close(sock);

        char* hdr_end = strstr(out_buf, "\r\n\r\n");
        if (!hdr_end) {
            *out_len = total;
            return 0;
        }
        *hdr_end = '\0';
        int status_code = 200;
        const char* sp = strchr(out_buf, ' ');
        if (sp) status_code = atoi(sp + 1);

        // Follow HTTP 301/302/303/307/308 redirects automatically!
        if (status_code == 301 || status_code == 302 || status_code == 303 ||
            status_code == 307 || status_code == 308) {
            const char* loc = nullptr;
            for (const char* line = out_buf; line && *line; ) {
                if (strncasecmp(line, "Location:", 9) == 0) {
                    loc = line + 9;
                    while (*loc == ' ' || *loc == '\t') loc++;
                    break;
                }
                const char* nl = strstr(line, "\r\n");
                line = nl ? nl + 2 : nullptr;
            }
            if (loc) {
                char next_url[1024] = {};
                const char* eol = strstr(loc, "\r\n");
                size_t llen = eol ? static_cast<size_t>(eol - loc) : strlen(loc);
                if (llen >= sizeof(next_url)) llen = sizeof(next_url) - 1;
                if (strncmp(loc, "http://", 7) == 0 || strncmp(loc, "https://", 8) == 0) {
                    memcpy(next_url, loc, llen);
                    next_url[llen] = '\0';
                } else if (loc[0] == '/') {
                    snprintf(next_url, sizeof(next_url), "%s://%s%.*s",
                             is_https ? "https" : "http", host, static_cast<int>(llen), loc);
                }
                if (next_url[0]) {
                    strncpy(cur_url, next_url, sizeof(cur_url) - 1);
                    cur_url[sizeof(cur_url) - 1] = '\0';
                    continue;
                }
            }
        }

        bool is_chunked = (strcasestr(out_buf, "Transfer-Encoding: chunked") != nullptr);
        char* body = hdr_end + 4;
        size_t body_len = total - static_cast<size_t>(body - out_buf);
        memmove(out_buf, body, body_len);
        if (is_chunked) {
            body_len = decode_chunked_inplace(out_buf, body_len);
        }
        out_buf[body_len] = '\0';
        *out_len = body_len;
        return 0;
    }
    if (err_buf) snprintf(err_buf, err_cap, "Too many redirects");
    return -ELOOP;
}

#else

void* pulih_input_open(void) { return nullptr; }
int pulih_input_rescan(void*) { return 0; }
int pulih_input_count(void*, int* x, int* y) {
    if (x) *x = 0;
    if (y) *y = 0;
    return 0;
}
int pulih_input_poll(void*, int, PulihRawEvent*, int) { return 0; }
void pulih_input_close(void*) {}
int pulih_haptic_click(uint32_t) { return -ENOSYS; }

struct PulihDmExtent {
    uint64_t logical_sector;
    uint64_t num_sectors;
    uint64_t physical_sector;
    uint32_t target_type;
};
int pulih_dm_map_ro(const char*, const char*, const PulihDmExtent*, uint32_t) { return -ENOSYS; }
int pulih_dm_remove(const char*) { return -ENOSYS; }
int pulih_http_fetch(const char*, char*, size_t, size_t*, char*, size_t) { return -ENOSYS; }

#endif

}  // extern "C"
