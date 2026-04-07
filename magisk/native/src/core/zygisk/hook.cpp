#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <limits.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unwind.h>
#include <link.h>
#include <cstdlib>
#include <cstdarg>
#include <span>

#include <lsplt.hpp>

#include <base.hpp>

#include "zygisk.hpp"
#include "module.hpp"
#include "jni_hooks.hpp"

using namespace std;

// *********************
// Zygisk Bootstrapping
// *********************
//
// Zygisk's lifecycle is driven by several PLT function hooks in libandroid_runtime, libart, and
// libnative_bridge. As Zygote is starting up, these carefully selected functions will call into
// the respective lifecycle callbacks in Zygisk to drive the progress forward.
//
// The entire bootstrap process is shown in the graph below.
// Arrows represent control flow, and the blocks are sorted chronologically from top to bottom.
//
// libnative_bridge       libandroid_runtime                zygisk                 libart
//
//                            ┌───────┐
//                            │ start │
//                            └───┬─┬─┘
//                                │ │                                         ┌────────────────┐
//                                │ └────────────────────────────────────────►│LoadNativeBridge│
//                                │                                           └───────┬────────┘
// ┌────────────────┐             │                                                   │
// │LoadNativeBridge│◄────────────┼───────────────────────────────────────────────────┘
// └───────┬────┬───┘             │
//         │    │                 │                     ┌───────────────┐
//         │    └─────────────────┼────────────────────►│NativeBridgeItf│
//         │                      │                     └──────┬────────┘
//         │                      │                            │
//         │                      │                            ▼
//         │                      │                        ┌────────┐
//         │                      │                        │hook_plt│
//         ▼                      │                        └────────┘
//     ┌───────┐                  │
//     │dlclose│                  │
//     └───┬───┘                  │
//         │                      │
//         │                      │                 ┌───────────────────────┐
//         └──────────────────────┼────────────────►│post_native_bridge_load│
//                                │                 └───────────────────────┘
//                                ▼
//                    ┌──────────────────────┐
//                    │ strdup("ZygoteInit") │
//                    └───────────┬────┬─────┘
//                                │    │                ┌───────────────┐
//                                │    └───────────────►│hook_zygote_jni│
//                                │                     └───────────────┘       ┌─────────┐
//                                │                                             │         │
//                                └────────────────────────────────────────────►│   JVM   │
//                                                                              │         │
//                                                                              └──┬─┬────┘
//                      ┌───────────────────┐                                      │ │
//                      │nativeXXXSpecialize│◄─────────────────────────────────────┘ │
//                      └─────────────┬─────┘                                        │
//                                    │                 ┌─────────────┐              │
//                                    └────────────────►│ZygiskContext│              │
//                                                      └─────────────┘              ▼
//                                                                         ┌────────────────────┐
//                                                                         │pthread_attr_destroy│
//                                                                         └─────────┬──────────┘
//                                                     ┌────────────────┐            │
//                                                     │restore_plt_hook│◄───────────┘
//                                                     └────────────────┘
//
// Some notes regarding the important functions/symbols during bootstrap:
//
// * NativeBridgeItf: this symbol is the entry point for android::LoadNativeBridge
// * HookContext::hook_plt(): hook functions like |dlclose| and |strdup|
// * dlclose: the final step in android::LoadNativeBridge. In this function, we unwind the call
//   stack to load the real native bridge if necessary, and fetch NativeBridgeRuntimeCallbacks.
// * strdup: called in AndroidRuntime::start before calling ZygoteInit#main(...)
// * HookContext::hook_zygote_jni(): replace the process specialization functions registered
//   with register_jni_procs. This marks the final step of the code injection bootstrap process.
// * pthread_attr_destroy: called whenever the JVM tries to setup threads for itself. We use
//   this method to cleanup and unload Zygisk from the process.

constexpr const char *kZygoteInit = "com.android.internal.os.ZygoteInit";
constexpr const char *kZygote = "com/android/internal/os/Zygote";
constexpr const char *kForkApp = "nativeForkAndSpecialize";
constexpr const char *kSpecializeApp = "nativeSpecializeAppProcess";
constexpr const char *kForkServer = "nativeForkSystemServer";

using JNIMethods = std::span<JNINativeMethod>;
using JNIMethodsDyn = std::pair<unique_ptr<JNINativeMethod[]>, size_t>;

struct HookContext : JniHookDefinitions {

    vector<tuple<dev_t, ino_t, const char *, void **>> plt_backup;
    const NativeBridgeRuntimeCallbacks *runtime_callbacks = nullptr;
    void *self_handle = nullptr;
    bool should_unmap = false;

    void hook_plt();
    void hook_unloader();
    void restore_plt_hook();
    void hook_zygote_jni();
    void restore_zygote_hook(JNIEnv *env);
    void hook_jni_methods(JNIEnv *env, const char *clz, JNIMethods methods) const;
    void post_native_bridge_load(void *handle);

private:
    void register_hook(dev_t dev, ino_t inode, const char *symbol, void *new_func, void **old_func);
    int hook_jni_methods(JNIEnv *env, jclass clazz, JNIMethods methods) const;
    JNIMethodsDyn get_jni_methods(JNIEnv *env, jclass clazz) const;
};

// -----------------------------------------------------------------

// Global contexts:
//
// HookContext lives as long as Zygisk is loaded in memory. It tracks the process's function
// hooking state and bootstraps code injection until we replace the process specialization methods.
//
// ZygiskContext lives during the process specialization process. It implements Zygisk
// features, such as loading modules and customizing process fork/specialization.

ZygiskContext *g_ctx;
static HookContext *g_hook;

static JniHookDefinitions *get_defs() {
    return g_hook;
}

// -----------------------------------------------------------------

#define DCL_HOOK_FUNC(ret, func, ...) \
ret (*old_##func)(__VA_ARGS__);       \
ret new_##func(__VA_ARGS__)

DCL_HOOK_FUNC(static char *, strdup, const char * str) {
    if (strcmp(kZygoteInit, str) == 0) {
        g_hook->hook_zygote_jni();
    }
    return old_strdup(str);
}

// Skip actual fork and return cached result if applicable
DCL_HOOK_FUNC(int, fork) {
    return (g_ctx && g_ctx->pid >= 0) ? g_ctx->pid : old_fork();
}

// Unmount stuffs in the process's private mount namespace
DCL_HOOK_FUNC(static int, unshare, int flags) {
    int res = old_unshare(flags);
    if (g_ctx && (flags & CLONE_NEWNS) != 0 && res == 0) {
        if (g_ctx->flags & DO_REVERT_UNMOUNT) {
            revert_unmount();
        }
        // Restore errno back to 0
        errno = 0;
    }
    return res;
}

// This is the last moment before the secontext of the process changes
DCL_HOOK_FUNC(static int, selinux_android_setcontext,
              uid_t uid, bool isSystemServer, const char *seinfo, const char *pkgname) {
    // Pre-fetch logd before secontext transition
    zygisk_get_logd();
    return old_selinux_android_setcontext(uid, isSystemServer, seinfo, pkgname);
}

// Close file descriptors to prevent crashing
DCL_HOOK_FUNC(static void, android_log_close) {
    if (g_ctx == nullptr || !(g_ctx->flags & SKIP_CLOSE_LOG_PIPE)) {
        // This happens during forks like nativeForkApp, nativeForkUsap,
        // nativeForkSystemServer, and nativeForkAndSpecialize.
        zygisk_close_logd();
    }
    old_android_log_close();
}

// It should be safe to assume all dlclose's in libnativebridge are for zygisk_loader
DCL_HOOK_FUNC(static int, dlclose, void *handle) {
    if (!g_hook->self_handle) {
        ZLOGV("dlclose zygisk_loader\n");
        g_hook->post_native_bridge_load(handle);
    }
    return 0;
}

// =====================================================================
// Detection Hiding: Master enable flag
// =====================================================================
// Activated during hook_plt() (Zygote bootstrap) and deactivated in
// pthread_attr_destroy before restore_plt_hook(). All three phases
// check this flag before applying any filtering.

static bool zygisk_hide_active = false;

// We cannot directly call `dlclose` to unload ourselves, otherwise when `dlclose` returns,
// it will return to our code which has been unmapped, causing segmentation fault.
// Instead, we hook `pthread_attr_destroy` which will be called when VM daemon threads start.
DCL_HOOK_FUNC(static int, pthread_attr_destroy, void *target) {
    int res = old_pthread_attr_destroy((pthread_attr_t *)target);

    // Only perform unloading on the main thread
    if (gettid() != getpid())
        return res;

    ZLOGV("pthread_attr_destroy\n");
    if (g_hook->should_unmap) {
        // Phase 1: Disable detection hiding before restoring hooks
        zygisk_hide_active = false;
        g_hook->restore_plt_hook();
        if (g_hook->should_unmap) {
            ZLOGV("dlclosing self\n");
            void *self_handle = g_hook->self_handle;
            delete g_hook;

            // Because both `pthread_attr_destroy` and `dlclose` have the same function signature,
            // we can use `musttail` to let the compiler reuse our stack frame and thus
            // `dlclose` will directly return to the caller of `pthread_attr_destroy`.
            [[clang::musttail]] return dlclose(self_handle);
        }
    }

    delete g_hook;
    return res;
}

#undef DCL_HOOK_FUNC

// =====================================================================
// Phase 1: Detection Hiding — dl_iterate_phdr filtering
// =====================================================================
// Filters out libzygisk.so entries from dl_iterate_phdr to prevent
// detection tools from discovering Zygisk through linker introspection.
// The hook is installed in libandroid_runtime.so and libart.so PLTs
// to cover the broadest range of callers within the Zygote process.

using phdr_cb_t = int (*)(struct dl_phdr_info *, size_t, void *);
// Separate backup pointers per library to ensure correct PLT restoration.
// Each library's GOT entry has its own original address; sharing a single
// pointer would cause the second registration to overwrite the first.
static int (*orig_dl_iterate_phdr_runtime)(phdr_cb_t, void *) = nullptr;
static int (*orig_dl_iterate_phdr_art)(phdr_cb_t, void *) = nullptr;

// =====================================================================
// Module Hook Chain Protection
// =====================================================================
// Modules may have already registered PLT hooks on libart.so for the same
// symbols that OniMask phases use (openat, readlink, dl_iterate_phdr).
// Since hook_unloader() runs AFTER module preAppSpecialize(), OniMask's
// register_hook() would overwrite the module's GOT entry.
//
// Solution: Before OniMask registers, snapshot the current GOT value.
// If it differs from what we expect (original libc function), a module
// has hooked it. We store the module's hook as a "chained" handler and
// OniMask's wrapper calls it after applying detection filtering.
//
// Chain order: Caller -> OniMask filter -> Module hook -> Original libc
//
// art_dev/art_inode are stored here for potential use by other components.

static dev_t  g_art_dev = 0;
static ino_t  g_art_inode = 0;

// Chained module hooks (set in hook_unloader if a module pre-hooked these)
static int (*chained_openat)(int, const char *, int, ...) = nullptr;
static ssize_t (*chained_readlink)(const char *, char *, size_t) = nullptr;
static int (*chained_dl_iterate_phdr_art)(phdr_cb_t, void *) = nullptr;

struct phdr_filter_ctx {
    phdr_cb_t user_cb;
    void *user_data;
};

static int phdr_filter_callback(struct dl_phdr_info *info, size_t size, void *data) {
    auto *ctx = static_cast<phdr_filter_ctx *>(data);

    // Filter entries matching libzygisk.so
    if (info->dlpi_name && strstr(info->dlpi_name, ZYGISKLDR)) {
        ZLOGV("hide: filtered dl_phdr entry [%s]\n", info->dlpi_name);
        return 0; // Continue iteration, skip this entry
    }

    return ctx->user_cb(info, size, ctx->user_data);
}

static int new_dl_iterate_phdr(phdr_cb_t callback, void *data) {
    if (!orig_dl_iterate_phdr_runtime) {
        orig_dl_iterate_phdr_runtime = (decltype(orig_dl_iterate_phdr_runtime))
            dlsym(RTLD_DEFAULT, "dl_iterate_phdr");
        orig_dl_iterate_phdr_art = orig_dl_iterate_phdr_runtime;
    }
    if (!orig_dl_iterate_phdr_runtime) return 0;

    if (!zygisk_hide_active) {
        return orig_dl_iterate_phdr_runtime(callback, data);
    }

    phdr_filter_ctx ctx{callback, data};
    return orig_dl_iterate_phdr_runtime(phdr_filter_callback, &ctx);
}

// =====================================================================
// Phase 2: /proc/self/maps Sanitization — openat filtering
// =====================================================================
// Intercepts openat() calls targeting /proc/self/maps or /proc/<pid>/maps.
// Returns a seekable anonymous file (memfd) containing filtered maps content
// with all libzygisk.so lines removed. Falls back to a pipe if memfd_create
// is unavailable (not seekable, but sufficient for sequential readers).
//
// Installed in libart.so PLT only — ART is the primary maps consumer through
// Java-level I/O. Zygisk internals (lsplt::MapInfo::Scan, xopen_dir) read maps
// and fd directories through libc, bypassing libart's PLT entirely.

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int (*orig_openat)(int, const char *, int, ...) = nullptr;

static int do_openat(int dirfd, const char *pathname, int flags, int mode) {
    // Chain: call module hook if one was registered before OniMask
    if (chained_openat) {
        return chained_openat(dirfd, pathname, flags, mode);
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

static bool is_proc_maps_path(const char *pathname) {
    if (!pathname) return false;
    // Fast reject: most paths don't start with '/' or second char isn't 'p'
    if (pathname[0] != '/' || pathname[1] != 'p') return false;
    if (strncmp(pathname, "/proc/", 6) != 0) return false;
    // Check for "/maps" suffix (5 chars) with minimum viable path length
    size_t len = strlen(pathname);
    if (len < 11) return false; // minimum: "/proc/1/maps"
    if (strcmp(pathname + len - 5, "/maps") != 0) return false;
    return true;
}

static bool is_zygisk_maps_line(const char *line, size_t line_len) {
    // Fast reject: ZYGISKLDR = "libzygisk.so" (12 chars), must fit in line
    if (line_len < sizeof(ZYGISKLDR) - 1) return false;
    // Use memmem for substring search; falls back to strstr on some libc
    const char *needle = ZYGISKLDR;
    size_t needle_len = sizeof(ZYGISKLDR) - 1;
    const void *found = nullptr;
#if defined(__has_builtin)
    #if __has_builtin(__builtin_memmem)
    found = __builtin_memmem(line, line_len, needle, needle_len);
    #else
    found = strstr(line, needle);
    #endif
#else
    found = strstr(line, needle);
#endif
    return found != nullptr;
}

// Write all bytes, handling partial writes and EINTR.
// Returns true on full success, false on any write error.
static bool write_all(int fd, const char *buf, size_t count) {
    while (count > 0) {
        ssize_t n = write(fd, buf, count);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        buf += n;
        count -= static_cast<size_t>(n);
    }
    return true;
}

static int new_openat(int dirfd, const char *pathname, int flags, ...) {
    // Extract mode_t when O_CREAT is set (variadic argument)
    int mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    // Fast path: if not hiding or path is not maps, pass through chain
    if (!zygisk_hide_active || !is_proc_maps_path(pathname)) {
        return do_openat(dirfd, pathname, flags, mode);
    }

    // Open the real maps file to read its content
    int real_fd = orig_openat(dirfd, pathname, flags, mode);
    if (real_fd < 0) return real_fd;

    // Read entire maps content into memory
    string content;
    char buf[4096];
    ssize_t n;
    while ((n = read(real_fd, buf, sizeof(buf))) > 0) {
        content.append(buf, static_cast<size_t>(n));
    }
    close(real_fd);

    if (n < 0) {
        // Read error — re-open original for the caller (degraded: unfiltered)
        return orig_openat(dirfd, pathname, flags, mode);
    }

    // Filter: build output with all lines EXCEPT those referencing Zygisk
    string filtered;
    filtered.reserve(content.size());
    size_t pos = 0;
    while (pos < content.size()) {
        size_t nl = content.find('\n', pos);
        size_t line_end = (nl != string::npos) ? nl : content.size();
        size_t next_pos = (nl != string::npos) ? nl + 1 : content.size();

        if (!is_zygisk_maps_line(content.data() + pos, line_end - pos)) {
            filtered.append(content, pos, next_pos - pos);
        } else {
            ZLOGV("hide: filtered maps line\n");
        }

        pos = next_pos;
    }

    // Create anonymous file with filtered content (seekable)
    // Respect caller's O_CLOEXEC: only set MFD_CLOEXEC when requested.
    const bool caller_wants_cloexec = (flags & O_CLOEXEC) != 0;
    int out_fd = syscall(__NR_memfd_create, "maps",
        caller_wants_cloexec ? MFD_CLOEXEC : 0);
    if (out_fd >= 0) {
        if (!write_all(out_fd, filtered.data(), filtered.size())) {
            close(out_fd);
            out_fd = -1;
        } else {
            lseek(out_fd, 0, SEEK_SET);
        }
    }

    // Fallback: use pipe (not seekable, but works for sequential readers)
    if (out_fd < 0) {
        int pipefd[2];
        if (pipe2(pipefd, caller_wants_cloexec ? O_CLOEXEC : 0) == 0) {
            write_all(pipefd[1], filtered.data(), filtered.size());
            close(pipefd[1]);
            out_fd = pipefd[0];
        }
    }

    // Last resort: pass through hook chain (app sees Zygisk, but won't crash)
    if (out_fd < 0) {
        return do_openat(dirfd, pathname, flags, mode);
    }

    return out_fd;
}

// =====================================================================
// Phase 3: /proc/self/fd Sanitization — readlink filtering
// =====================================================================
// Intercepts readlink() calls on /proc/self/fd/* and /proc/<pid>/fd/*.
// If the symlink target points to a Zygisk-related file (contains
// libzygisk.so in the path), the result is replaced with "/dev/null".
//
// Installed in libart.so PLT only. Zygisk internals use opendir/readdir
// on /proc/self/fd through libc (not libart's PLT), so they are unaffected.

static ssize_t (*orig_readlink)(const char *, char *, size_t) = nullptr;

static ssize_t do_readlink(const char *pathname, char *buf, size_t bufsiz) {
    // Chain: call module hook if one was registered before OniMask
    if (chained_readlink) {
        return chained_readlink(pathname, buf, bufsiz);
    }
    return orig_readlink(pathname, buf, bufsiz);
}

static bool is_proc_fd_path(const char *pathname) {
    if (!pathname) return false;
    if (strncmp(pathname, "/proc/", 6) != 0) return false;
    // Must contain "/fd/" after the /proc/ prefix
    const char *fd_marker = strstr(pathname + 6, "/fd/");
    return fd_marker != nullptr;
}

static ssize_t new_readlink(const char *pathname, char *buf, size_t bufsiz) {
    ssize_t ret = orig_readlink(pathname, buf, bufsiz);

    // Only filter when hiding is active, readlink succeeded, and path is /proc/*/fd/*
    if (!zygisk_hide_active || ret <= 0 || !is_proc_fd_path(pathname)) {
        return ret;
    }

    // If a module pre-hooked readlink, call it first, then filter the result.
    // This allows modules to transform the symlink target before OniMask
    // checks for Zygisk-related paths.
    if (chained_readlink && ret > 0) {
        char chain_buf[PATH_MAX];
        ssize_t chain_ret = chained_readlink(pathname, chain_buf,
            static_cast<size_t>(ret) < sizeof(chain_buf)
                ? static_cast<size_t>(ret) + 1 : sizeof(chain_buf));
        if (chain_ret > 0) {
            ret = chain_ret;
            memcpy(buf, chain_buf,
                static_cast<size_t>(ret) < bufsiz ? static_cast<size_t>(ret) : bufsiz);
            // Null-terminate for subsequent strstr check
            size_t ret_len = static_cast<size_t>(ret);
            if (ret_len < bufsiz) buf[ret_len] = '\0';
            else if (bufsiz > 0) buf[bufsiz - 1] = '\0';
        }
    }

    // Null-terminate the result for safe string operations
    // (readlink does NOT null-terminate on success)
    size_t ret_len = static_cast<size_t>(ret);
    if (ret_len < bufsiz) {
        buf[ret_len] = '\0';
    } else if (bufsiz > 0) {
        buf[bufsiz - 1] = '\0';
    }

    // If the symlink target references a Zygisk library, replace with /dev/null
    if (strstr(buf, ZYGISKLDR) != nullptr) {
        const char dev_null[] = "/dev/null";
        size_t dlen = sizeof(dev_null) - 1; // 9, no null terminator in count
        if (dlen <= bufsiz) {
            memcpy(buf, dev_null, dlen);
            ZLOGV("hide: redirected fd symlink to /dev/null\n");
            return static_cast<ssize_t>(dlen);
        }
    }

    return ret;
}

// -----------------------------------------------------------------

static size_t get_fd_max() {
    rlimit r{32768, 32768};
    getrlimit(RLIMIT_NOFILE, &r);
    return r.rlim_max;
}

ZygiskContext::ZygiskContext(JNIEnv *env, void *args) :
    env(env), args{args}, process(nullptr), pid(-1), flags(0), info_flags(0),
    allowed_fds(get_fd_max()), hook_info_lock(PTHREAD_MUTEX_INITIALIZER) { g_ctx = this; }

ZygiskContext::~ZygiskContext() {
    // This global pointer points to a variable on the stack.
    // Set this to nullptr to prevent leaking local variable.
    // This also disables most plt hooked functions.
    g_ctx = nullptr;

    if (!is_child())
        return;

    // Phase 1: Clean up detection environment variables.
    // Preserve ZYGISK_ENABLED for the Magisk Manager app — it is intentionally
    // set in app_specialize_post() (module.cpp) for Zygisk status detection.
    if (!(info_flags & +ZygiskStateFlags::ProcessIsMagiskApp)) {
        unsetenv("ZYGISK_ENABLED");
    }

    zygisk_close_logd();
    android_logging();

    // Strip out all API function pointers
    for (auto &m : modules) {
        m.clearApi();
    }

    // Cleanup
    g_hook->should_unmap = true;
    g_hook->restore_zygote_hook(env);
    g_hook->hook_unloader();
}

// -----------------------------------------------------------------

inline void *unwind_get_region_start(_Unwind_Context *ctx) {
    auto fp = _Unwind_GetRegionStart(ctx);
#if defined(__arm__)
    // On arm32, we need to check if the pc is in thumb mode,
    // if so, we need to set the lowest bit of fp to 1
    auto pc = _Unwind_GetGR(ctx, 15); // r15 is pc
    if (pc & 1) {
        // Thumb mode
        fp |= 1;
    }
#endif
    return reinterpret_cast<void *>(fp);
}

// As we use NativeBridgeRuntimeCallbacks to reload native bridge and to hook jni functions,
// we need to find it by the native bridge's unwind context.
// For abis that use registers to pass arguments, i.e. arm32, arm64, x86_64, the registers are
// caller-saved, and they are not preserved in the unwind context. However, they will be saved
// into the callee-saved registers, so we will search the callee-saved registers for the second
// argument, which is the pointer to NativeBridgeRuntimeCallbacks.
// For x86, whose abi uses stack to pass arguments, we can directly get the pointer to
// NativeBridgeRuntimeCallbacks from the stack.
static const NativeBridgeRuntimeCallbacks* find_runtime_callbacks(struct _Unwind_Context *ctx) {
    // Find the writable memory region of libart.so, where the NativeBridgeRuntimeCallbacks is located.
    auto [start, end] = []()-> tuple<uintptr_t, uintptr_t> {
        for (const auto &map : lsplt::MapInfo::Scan()) {
            if (map.path.ends_with("/libart.so") && map.perms == (PROT_WRITE | PROT_READ)) {
                ZLOGV("libart.so: start=%p, end=%p\n",
                      reinterpret_cast<void *>(map.start), reinterpret_cast<void *>(map.end));
                return {map.start, map.end};
            }
        }
        return {0, 0};
    }();
#if defined(__aarch64__)
    // r19-r28 are callee-saved registers
    for (int i = 19; i <= 28; ++i) {
        auto val = static_cast<uintptr_t>(_Unwind_GetGR(ctx, i));
        ZLOGV("r%d = %p\n", i, reinterpret_cast<void *>(val));
        if (val >= start && val < end)
            return reinterpret_cast<const NativeBridgeRuntimeCallbacks*>(val);
    }
#elif defined(__arm__)
    // r4-r10 are callee-saved registers
    for (int i = 4; i <= 10; ++i) {
        auto val = static_cast<uintptr_t>(_Unwind_GetGR(ctx, i));
        ZLOGV("r%d = %p\n", i, reinterpret_cast<void *>(val));
        if (val >= start && val < end)
            return reinterpret_cast<const NativeBridgeRuntimeCallbacks*>(val);
    }
#elif defined(__i386__)
    // get ebp, which points to the bottom of the stack frame
    auto ebp = static_cast<uintptr_t>(_Unwind_GetGR(ctx, 5));
    // 1 pointer size above ebp is the old ebp
    // 2 pointer sizes above ebp is the return address
    // 3 pointer sizes above ebp is the 2nd arg
    auto val = *reinterpret_cast<uintptr_t *>(ebp + 3 * sizeof(void *));
    ZLOGV("ebp + 3 * ptr_size = %p\n", reinterpret_cast<void *>(val));
    if (val >= start && val < end)
        return reinterpret_cast<const NativeBridgeRuntimeCallbacks*>(val);
#elif defined(__x86_64__)
    // r12-r15 and rbx are callee-saved registers, but the compiler is likely to use them reversely
    for (int i : {3, 15, 14, 13, 12}) {
        auto val = static_cast<uintptr_t>(_Unwind_GetGR(ctx, i));
        ZLOGV("r%d = %p\n", i, reinterpret_cast<void *>(val));
        if (val >= start && val < end)
            return reinterpret_cast<const NativeBridgeRuntimeCallbacks*>(val);
    }
#elif defined(__riscv)
    // x8-x9, x18-x27 callee-saved registers
    for (int i : {8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}) {
        auto val = static_cast<uintptr_t>(_Unwind_GetGR(ctx, i));
        ZLOGV("x%d = %p\n", i, reinterpret_cast<void *>(val));
        if (val >= start && val < end)
            return reinterpret_cast<const NativeBridgeRuntimeCallbacks*>(val);
    }
#else
#error "Unsupported architecture"
#endif
    return nullptr;
}

void HookContext::post_native_bridge_load(void *handle) {
    self_handle = handle;
    using method_sig = const bool (*)(const char *, const NativeBridgeRuntimeCallbacks *);
    struct trace_arg {
        method_sig load_native_bridge;
        const NativeBridgeRuntimeCallbacks *callbacks;
    };
    trace_arg arg{};

    // Unwind to find the address of android::LoadNativeBridge and NativeBridgeRuntimeCallbacks
    _Unwind_Backtrace(+[](_Unwind_Context *ctx, void *arg) -> _Unwind_Reason_Code {
        void *fp = unwind_get_region_start(ctx);
        Dl_info info{};
        dladdr(fp, &info);
        ZLOGV("backtrace: %p %s\n", fp, info.dli_fname ?: "???");
        if (info.dli_fname && std::string_view(info.dli_fname).ends_with("/libnativebridge.so")) {
            auto payload = reinterpret_cast<trace_arg *>(arg);
            payload->load_native_bridge = reinterpret_cast<method_sig>(fp);
            payload->callbacks = find_runtime_callbacks(ctx);
            ZLOGV("NativeBridgeRuntimeCallbacks: %p\n", payload->callbacks);
            return _URC_END_OF_STACK;
        }
        return _URC_NO_REASON;
    }, &arg);

    if (!arg.load_native_bridge || !arg.callbacks)
        return;

    // Reload the real native bridge if necessary
    auto nb = get_prop(NBPROP);
    auto len = sizeof(ZYGISKLDR) - 1;
    if (nb.size() > len) {
        arg.load_native_bridge(nb.c_str() + len, arg.callbacks);
    }
    runtime_callbacks = arg.callbacks;
}

// -----------------------------------------------------------------

void HookContext::register_hook(
        dev_t dev, ino_t inode, const char *symbol, void *new_func, void **old_func) {
    if (!lsplt::RegisterHook(dev, inode, symbol, new_func, old_func)) {
        ZLOGE("Failed to register plt_hook \"%s\"\n", symbol);
        return;
    }
    plt_backup.emplace_back(dev, inode, symbol, old_func);
}

#define PLT_HOOK_REGISTER_SYM(DEV, INODE, SYM, NAME) \
    register_hook(DEV, INODE, SYM, \
    reinterpret_cast<void *>(new_##NAME), reinterpret_cast<void **>(&old_##NAME))

#define PLT_HOOK_REGISTER(DEV, INODE, NAME) \
    PLT_HOOK_REGISTER_SYM(DEV, INODE, #NAME, NAME)

void HookContext::hook_plt() {
    ino_t android_runtime_inode = 0;
    dev_t android_runtime_dev = 0;
    ino_t native_bridge_inode = 0;
    dev_t native_bridge_dev = 0;

    for (auto &map : lsplt::MapInfo::Scan()) {
        if (map.path.ends_with("/libandroid_runtime.so")) {
            android_runtime_inode = map.inode;
            android_runtime_dev = map.dev;
        } else if (map.path.ends_with("/libnativebridge.so")) {
            native_bridge_inode = map.inode;
            native_bridge_dev = map.dev;
        }
    }

    PLT_HOOK_REGISTER(native_bridge_dev, native_bridge_inode, dlclose);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, fork);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, unshare);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, selinux_android_setcontext);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, strdup);
    PLT_HOOK_REGISTER_SYM(android_runtime_dev, android_runtime_inode, "__android_log_close", android_log_close);

    // Phase 1: Hook dl_iterate_phdr to filter Zygisk entries from linker introspection
    zygisk_hide_active = true;
    register_hook(android_runtime_dev, android_runtime_inode, "dl_iterate_phdr",
        reinterpret_cast<void *>(new_dl_iterate_phdr),
        reinterpret_cast<void **>(&orig_dl_iterate_phdr_runtime));

    if (!lsplt::CommitHook())
        ZLOGE("plt_hook failed\n");

    // Remove unhooked methods
    std::erase_if(plt_backup, [](auto &t) { return *std::get<3>(t) == nullptr; });
}

void HookContext::hook_unloader() {
    ino_t art_inode = 0;
    dev_t art_dev = 0;

    for (auto &map : lsplt::MapInfo::Scan()) {
        if (map.path.ends_with("/libart.so")) {
            art_inode = map.inode;
            art_dev = map.dev;
            break;
        }
    }

    // Store art device/inode for module hook chain detection
    g_art_dev = art_dev;
    g_art_inode = art_inode;

    // Detect if modules have already hooked the symbols we need.
    // Resolve the real libc function addresses for comparison.
    // If a module hooked these symbols, the GOT value will differ
    // from the real function, and we chain through the module's hook.
    auto real_openat = reinterpret_cast<int (*)(int, const char *, int, ...)>(
        dlsym(RTLD_DEFAULT, "openat"));
    auto real_readlink = reinterpret_cast<ssize_t (*)(const char *, char *, size_t)>(
        dlsym(RTLD_DEFAULT, "readlink"));
    auto real_dl_iterate_phdr = reinterpret_cast<int (*)(phdr_cb_t, void *)>(
        dlsym(RTLD_DEFAULT, "dl_iterate_phdr"));

    PLT_HOOK_REGISTER(art_dev, art_inode, pthread_attr_destroy);

    // Phase 1: Also hook dl_iterate_phdr in libart.so for broader coverage
    // Save current GOT value before overwriting (may be a module hook)
    {
        void *saved = nullptr;
        lsplt::RegisterHook(art_dev, art_inode, "dl_iterate_phdr",
            reinterpret_cast<void *>(new_dl_iterate_phdr), &saved);
        if (saved && saved != reinterpret_cast<void *>(real_dl_iterate_phdr)) {
            chained_dl_iterate_phdr_art =
                reinterpret_cast<int (*)(phdr_cb_t, void *)>(saved);
            ZLOGV("hide: chaining module dl_iterate_phdr hook\n");
        }
        orig_dl_iterate_phdr_art =
            reinterpret_cast<int (*)(phdr_cb_t, void *)>(saved);
        plt_backup.emplace_back(art_dev, art_inode, "dl_iterate_phdr",
            reinterpret_cast<void **>(&orig_dl_iterate_phdr_art));
    }

    // Phase 2: Hook openat in libart.so to sanitize /proc/self/maps content
    // Save current GOT value before overwriting (may be a module hook)
    {
        void *saved = nullptr;
        lsplt::RegisterHook(art_dev, art_inode, "openat",
            reinterpret_cast<void *>(new_openat), &saved);
        if (saved && saved != reinterpret_cast<void *>(real_openat)) {
            chained_openat =
                reinterpret_cast<int (*)(int, const char *, int, ...)>(saved);
            ZLOGV("hide: chaining module openat hook\n");
        }
        orig_openat =
            reinterpret_cast<int (*)(int, const char *, int, ...)>(saved);
        plt_backup.emplace_back(art_dev, art_inode, "openat",
            reinterpret_cast<void **>(&orig_openat));
    }

    // Phase 3: Hook readlink in libart.so to sanitize /proc/self/fd symlink targets
    // Save current GOT value before overwriting (may be a module hook)
    {
        void *saved = nullptr;
        lsplt::RegisterHook(art_dev, art_inode, "readlink",
            reinterpret_cast<void *>(new_readlink), &saved);
        if (saved && saved != reinterpret_cast<void *>(real_readlink)) {
            chained_readlink =
                reinterpret_cast<ssize_t (*)(const char *, char *, size_t)>(saved);
            ZLOGV("hide: chaining module readlink hook\n");
        }
        orig_readlink =
            reinterpret_cast<ssize_t (*)(const char *, char *, size_t)>(saved);
        plt_backup.emplace_back(art_dev, art_inode, "readlink",
            reinterpret_cast<void **>(&orig_readlink));
    }

    if (!lsplt::CommitHook())
        ZLOGE("plt_hook failed\n");
}

void HookContext::restore_plt_hook() {
    // Unhook plt_hook
    for (const auto &[dev, inode, sym, old_func] : plt_backup) {
        if (!lsplt::RegisterHook(dev, inode, sym, *old_func, nullptr)) {
            ZLOGE("Failed to register plt_hook [%s]\n", sym);
            should_unmap = false;
        }
    }
    if (!lsplt::CommitHook()) {
        ZLOGE("Failed to restore plt_hook\n");
        should_unmap = false;
    }
}

// -----------------------------------------------------------------

JNIMethodsDyn HookContext::get_jni_methods(JNIEnv *env, jclass clazz) const {
    size_t total = runtime_callbacks->getNativeMethodCount(env, clazz);
    auto methods = std::make_unique_for_overwrite<JNINativeMethod[]>(total);
    runtime_callbacks->getNativeMethods(env, clazz, methods.get(), total);
    return std::make_pair(std::move(methods), total);
}

static void register_jni_methods(JNIEnv *env, jclass clazz, JNIMethods methods) {
    for (auto &method : methods) {
        // It's useful to allow nullptr function pointer for restoring hook
        if (!method.fnPtr) continue;

        // It's normal that the method is not found
        if (env->RegisterNatives(clazz, &method, 1) == JNI_ERR || env->ExceptionCheck() == JNI_TRUE) {
            env->ExceptionClear();
            method.fnPtr = nullptr;
        }
    }
}

int HookContext::hook_jni_methods(JNIEnv *env, jclass clazz, JNIMethods methods) const {
    // Backup existing methods
    auto o = get_jni_methods(env, clazz);
    const auto old_methods = span(o.first.get(), o.second);

    // WARNING: the signature field returned from getNativeMethods is in a non-standard format.
    // DO NOT TRY TO USE IT. This is the reason why we try to call RegisterNatives on every single
    // provided JNI methods directly to be 100% sure about whether a signature matches or not.

    // Replace methods
    register_jni_methods(env, clazz, methods);

    // Fetch the new set of native methods
    auto n = get_jni_methods(env, clazz);
    const auto new_methods = span(n.first.get(), n.second);

    // Find the old function pointer and return to caller
    int hook_count = 0;
    for (auto &method : methods) {
        if (!method.fnPtr) continue;
        for (const auto &new_method : new_methods) {
            if (new_method.fnPtr == method.fnPtr) {
                for (const auto &old_method : old_methods) {
                    if (strcmp(old_method.name, new_method.name) == 0 &&
                        strcmp(old_method.signature, new_method.signature) == 0) {
                        ZLOGV("replace %s %s %p -> %p\n",
                            method.name, method.signature, old_method.fnPtr, method.fnPtr);
                        method.fnPtr = old_method.fnPtr;
                        ++hook_count;
                        // Break 2 levels of for loop
                        goto next_method;
                    }
                }
            }
        }
        next_method:
    }
    return hook_count;
}


void HookContext::hook_jni_methods(JNIEnv *env, const char *clz, JNIMethods methods) const {
    jclass clazz;
    if (!runtime_callbacks || !env || !clz || !((clazz = env->FindClass(clz)))) {
        ranges::for_each(methods, [](auto &m) { m.fnPtr = nullptr; });
        return;
    }
    hook_jni_methods(env, clazz, methods);
}

void HookContext::hook_zygote_jni() {
    using method_sig = jint(*)(JavaVM **, jsize, jsize *);
    auto get_created_vms = reinterpret_cast<method_sig>(
            dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
    if (!get_created_vms) {
        for (auto &map: lsplt::MapInfo::Scan()) {
            if (!map.path.ends_with("/libnativehelper.so")) continue;
            void *h = dlopen(map.path.data(), RTLD_LAZY);
            if (!h) {
                ZLOGW("Cannot dlopen libnativehelper.so: %s\n", dlerror());
                break;
            }
            get_created_vms = reinterpret_cast<method_sig>(dlsym(h, "JNI_GetCreatedJavaVMs"));
            dlclose(h);
            break;
        }
        if (!get_created_vms) {
            ZLOGW("JNI_GetCreatedJavaVMs not found\n");
            return;
        }
    }

    JavaVM *vm = nullptr;
    jsize num = 0;
    jint res = get_created_vms(&vm, 1, &num);
    if (res != JNI_OK || vm == nullptr) {
        ZLOGW("JavaVM not found\n");
        return;
    }
    JNIEnv *env = nullptr;
    res = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (res != JNI_OK || env == nullptr) {
        ZLOGW("JNIEnv not found\n");
    }

    JNINativeMethod missing_method{};
    bool replaced_fork_app = false;
    bool replaced_specialize_app = false;
    bool replaced_fork_server = false;

    jclass clazz = env->FindClass(kZygote);
    auto [ptr, count] = get_jni_methods(env, clazz);
    for (const auto methods = span(ptr.get(), count); const auto &method : methods) {
        if (strcmp(method.name, kForkApp) == 0) {
            if (hook_jni_methods(env, clazz, fork_app_methods) == 0) {
                missing_method = method;
                break;
            }
            replaced_fork_app = true;
        } else if (strcmp(method.name, kSpecializeApp) == 0) {
            if (hook_jni_methods(env, clazz, specialize_app_methods) == 0) {
                missing_method = method;
                break;
            }
            replaced_specialize_app = true;
        } else if (strcmp(method.name, kForkServer) == 0) {
            if (hook_jni_methods(env, clazz, fork_server_methods) == 0) {
                missing_method = method;
                break;
            }
            replaced_fork_server = true;
        }
    }

    if (missing_method.name != nullptr) {
        ZLOGE("Cannot hook method: %s %s\n", missing_method.name, missing_method.signature);
        // Restore methods that were already replaced
        if (replaced_fork_app) register_jni_methods(env, clazz, fork_app_methods);
        if (replaced_specialize_app) register_jni_methods(env, clazz, specialize_app_methods);
        if (replaced_fork_server) register_jni_methods(env, clazz, fork_server_methods);
        // Clear the method lists just in case
        ranges::for_each(fork_app_methods, [](auto &m) { m.fnPtr = nullptr; });
        ranges::for_each(specialize_app_methods, [](auto &m) { m.fnPtr = nullptr; });
        ranges::for_each(fork_server_methods, [](auto &m) { m.fnPtr = nullptr; });
    }
}

void HookContext::restore_zygote_hook(JNIEnv *env) {
    jclass clazz = env->FindClass(kZygote);
    register_jni_methods(env, clazz, fork_app_methods);
    register_jni_methods(env, clazz, specialize_app_methods);
    register_jni_methods(env, clazz, fork_server_methods);
}

// -----------------------------------------------------------------

void hook_entry() {
    default_new(g_hook);
    g_hook->hook_plt();
}

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods) {
    g_hook->hook_jni_methods(env, clz, { methods, static_cast<size_t>(numMethods) });
}
