# OniMask — Zygisk Upstream Reference & ReZygisk Integration Guide

> **Purpose**: Comprehensive reference for Magisk upstream Zygisk architecture and
> diff-ready integration map for porting features from ReZygisk (PerformanC/ReZygisk).
>
> **Audience**: OniMask developers updating zygisk features from ReZygisk.
>
> **Last updated**: 2026-04-07

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Magisk Zygisk — Complete Hook Map](#2-magisk-zygisk--complete-hook-map)
3. [Zygisk Lifecycle State Machine](#3-zygisk-lifecycle-state-machine)
4. [Module API Reference (v1–v5)](#4-module-api-reference-v1v5)
5. [Daemon IPC Protocol (Magisk)](#5-daemon-ipc-protocol-magisk)
6. [OniMask Patch Inventory](#6-onimask-patch-inventory)
7. [ReZygisk Architecture & Feature Map](#7-rezygisk-architecture--feature-map)
8. [ReZygisk vs Magisk Zygisk — Detailed Diff](#8-rezygisk-vs-magisk-zygisk--detailed-diff)
9. [Feature Porting Guide — ReZygisk → OniMask](#9-feature-porting-guide--rezygisk--onimask)
10. [File Cross-Reference](#10-file-cross-reference)

---

## 1. Architecture Overview

### 1.1 Magisk Zygisk (Upstream)

```
┌─────────────────────────────────────────────────────────────────┐
│                        Magisk Daemon (magiskd)                  │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ ZygiskState │  │ deny utils   │  │ module list / db         │  │
│  │ (daemon.rs) │  │ (utils.cpp)  │  │ (daemon.rs)              │  │
│  └─────┬──────┘  └──────┬───────┘  └───────────┬──────────────┘  │
│        │                │                     │                  │
│        └────────────────┼─────────────────────┘                  │
│                         │  Unix socket IPC                      │
│              ┌──────────▼──────────┐                            │
│              │  ZygiskRequest      │                            │
│              │  GetInfo            │                            │
│              │  ConnectCompanion   │                            │
│              │  GetModDir          │                            │
│              └─────────────────────┘                            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     Zygote Process                               │
│                                                                  │
│  ┌───────────────┐  via NBPROP trick                            │
│  │ libzygisk.so  │◄─────────────────────────┐                   │
│  │ (hook.cpp)    │                          │                   │
│  └───────┬───────┘                          │                   │
│          │ PLT hooks                        │                   │
│  ┌───────▼───────────────────────────────────────────────────┐  │
│  │ libandroid_runtime.so PLT                                  │  │
│  │  fork, unshare, selinux_android_setcontext, strdup,       │  │
│  │  __android_log_close, dlclose                              │  │
│  │  [OniMask] dl_iterate_phdr (Phase 1)                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────┬───────────────────────────────────────────────────┐  │
│  │ libart.so PLT                                             │  │
│  │  pthread_attr_destroy (unloader)                           │  │
│  │  [OniMask] dl_iterate_phdr (Phase 1)                       │  │
│  │  [OniMask] openat (Phase 2: maps sanitization)             │  │
│  │  [OniMask] readlink (Phase 3: fd sanitization)             │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ JNI Hooks (com/android/internal/os/Zygote)                │  │
│  │  nativeForkAndSpecialize (12 variants)                     │  │
│  │  nativeSpecializeAppProcess (7 variants)                   │  │
│  │  nativeForkSystemServer (2 variants)                       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 ReZygisk Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              ReZygisk Daemon (zygiskd64/32)                      │
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────────────┐   │
│  │ root impl    │  │ companion     │  │ mount namespace     │   │
│  │ (Magisk/KSU/ │  │ (per-module)  │  │ management          │   │
│  │  APatch)     │  │               │  │ (save_mns_fd)       │   │
│  └──────────────┘  └───────────────┘  └─────────────────────┘   │
│  Socket: /data/adb/rezygisk/cp{32,64}.sock                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│              Monitor Process (init ptrace)                       │
│  PTRACE_SEIZE init → PTRACE_O_TRACEFORK → detect Zygote fork   │
│  Forks tracer → inject_on_main() at AT_ENTRY                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     Zygote Process                               │
│  ┌────────────────┐    CSOLoader injection at AT_ENTRY           │
│  │ libzygisk.so   │◄── ptracer maps into memory                 │
│  └───────┬────────┘                                              │
│          │ PLT hooks (libandroid_runtime.so only)                │
│  ┌───────▼───────────────────────────────────────────────────┐  │
│  │ fork, strdup, property_get,                                │  │
│  │ FileDescriptorInfo::ReopenOrDetach (prefix match)           │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────┬───────────────────────────────────────────────────┐  │
│  │ libart.so PLT                                             │  │
│  │ pthread_attr_setstacksize (unloader via musttail munmap)   │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Magisk Zygisk — Complete Hook Map

### 2.1 PLT Hooks (hook.cpp)

| # | Symbol | Library | Type | Original Purpose | OniMask Phase |
|---|--------|---------|------|------------------|---------------|
| 1 | `dlclose` | libnativebridge.so | Bootstrap | Intercept zygisk_loader close → fetch NativeBridgeRuntimeCallbacks | — |
| 2 | `fork` | libandroid_runtime.so | Lifecycle | Skip real fork, return cached PID from Zygisk's own fork | — |
| 3 | `unshare` | libandroid_runtime.so | Mount ns | After `CLONE_NEWNS`, call `revert_unmount()` for denylisted apps | — |
| 4 | `selinux_android_setcontext` | libandroid_runtime.so | SELinux | Pre-fetch logd fd before secontext transition | — |
| 5 | `strdup` | libandroid_runtime.so | Bootstrap | Detect `"com.android.internal.os.ZygoteInit"` → trigger JNI hook setup | — |
| 6 | `__android_log_close` | libandroid_runtime.so | Logging | Close logd pipe fd before Zygote closes it | — |
| 7 | `pthread_attr_destroy` | libart.so | Unloader | On main thread: restore PLT hooks, `musttail dlclose(self)` | — |
| 8 | `dl_iterate_phdr` | libandroid_runtime.so + libart.so | **Phase 1** | Filter libzygisk.so entries from phdr iteration | OniMask |
| 9 | `openat` | libart.so | **Phase 2** | Sanitize /proc/self/maps content via memfd | OniMask |
| 10 | `readlink` | libart.so | **Phase 3** | Redirect Zygisk fd symlinks to /dev/null | OniMask |

### 2.2 JNI Hooks (jni_hooks.hpp — auto-generated by gen_jni_hooks.py)

| Method | Variants | Android Versions |
|--------|----------|-----------------|
| `nativeForkAndSpecialize` | 12 | L, O, P, Q, Q-alt, R, U, B, Samsung M/N/O/P, Nubia U |
| `nativeSpecializeAppProcess` | 7 | Q, Q-alt, R, U, XR-U, Samsung Q, Nubia U |
| `nativeForkSystemServer` | 2 | L, Samsung Q |

### 2.3 Hook Registration Macros

```cpp
#define PLT_HOOK_REGISTER(DEV, INODE, NAME) \
    PLT_HOOK_REGISTER_SYM(DEV, INODE, #NAME, NAME)

#define PLT_HOOK_REGISTER_SYM(DEV, INODE, SYM, NAME) \
    register_hook(DEV, INODE, SYM, \
    reinterpret_cast<void *>(new_##NAME), reinterpret_cast<void **>(&old_##NAME))
```

---

## 3. Zygisk Lifecycle State Machine

```
                    ┌──────────────────────────────────┐
                    │       Zygote starts               │
                    │  LoadNativeBridge("libzygisk.so") │
                    │  via ro.dalvik.vm.native.bridge   │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  NativeBridgeItf::isCompatibleWith│
                    │  → hook_entry()                   │
                    │  → hook_plt()                     │
                    │    [Phase 1 activated]            │
                    │    zygisk_hide_active = true      │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  post_native_bridge_load()        │
                    │  → Unwind call stack              │
                    │  → find_runtime_callbacks()       │
                    │  → Reload real native bridge      │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  strdup("ZygoteInit")            │
                    │  → hook_zygote_jni()             │
                    │  → Replace JNI methods           │
                    └──────────────┬───────────────────┘
                                   │
        ┌──────────────────────────┤──────────────────────────┐
        │ Zygote main              │ Zygote fork+specialize    │
        │ (idle loop)              │ (per-app)                │
        └──────────────────────────┼──────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  ZygiskContext constructor       │
                    │  g_ctx = this                    │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  nativeForkAndSpecialize_pre()   │
                    │  → fork_pre() [Zygisk forks first]│
                    │  → app_specialize_pre()          │
                    │    → get_module_info() [IPC]     │
                    │    → run_modules_pre()           │
                    │      → android_dlopen_ext() each │
                    │      → module.preAppSpecialize()│
                    │      → [module may pltHookReg]  │
                    │    → sanitize_fds()             │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  Original native method runs    │
                    │  (actual fork + specialize)      │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  nativeForkAndSpecialize_post()  │
                    │  → app_specialize_post()         │
                    │    → run_modules_post()          │
                    │      → module.postAppSpecialize()│
                    │      → module.tryUnload()       │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  ~ZygiskContext (destructor)     │
                    │  → g_ctx = nullptr               │
                    │  → unsetenv("ZYGISK_ENABLED")   │
                    │    [guarded by ProcessIsMagiskApp]│
                    │  → g_hook->should_unmap = true   │
                    │  → restore_zygote_hook(env)      │
                    │  → hook_unloader()               │
                    │    [Phase 1+2+3 hooks in libart] │
                    │    [Module hook chain detected] │
                    │    [CommitHook()]               │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  pthread_attr_destroy            │
                    │  [main thread only]              │
                    │  → zygisk_hide_active = false    │
                    │  → restore_plt_hook()           │
                    │  → delete g_hook                │
                    │  → [[musttail]] dlclose(self)   │
                    │  [libzygisk.so unmapped]        │
                    └──────────────────────────────────┘
```

---

## 4. Module API Reference (v1–v5)

### 4.1 Struct Layout (module.hpp / api.hpp)

```cpp
union ApiTable {
    api_abi_base base;   // impl, registerModule
    api_abi_v1   v1;     // v1 + hookJni, pltHookReg(regex), pltHookExclude, commit, companion, setOption
    api_abi_v2   v2;     // v2 + getModuleDir, getFlags
    api_abi_v4   v4;     // v4 + pltHookReg(dev,ino), exemptFd
};
```

### 4.2 API Methods

| Method | Since | Thread | Purpose |
|--------|-------|--------|---------|
| `hookJniNativeMethods(env, cls, methods, n)` | v1 | pre | Replace JNI native methods for a class |
| `pltHookRegister(regex, sym, fn, backup)` | v1 | pre | Register PLT hook by path regex (v1-v3 ABI) |
| `pltHookExclude(regex, sym)` | v1 | pre | Exclude matched libs from hook registration |
| `pltHookCommit()` | v1 | pre | Commit all registered PLT hooks |
| `connectCompanion()` | v1 | pre | Connect to root companion daemon socket |
| `setOption(opt)` | v1 | pre | Set options (FORCE_DENYLIST_UNMOUNT, DLCLOSE_MODULE_LIBRARY) |
| `getModuleDir()` | v2 | pre | Get module's data directory fd |
| `getFlags()` | v2 | any | Get process flags (ROOT_GRANTED, ON_DENYLIST) |
| `pltHookRegister(dev, inode, sym, fn, backup)` | v4 | pre | Register PLT hook by device/inode (direct lsplt) |
| `exemptFd(fd)` | v4 | pre | Prevent Zygote from closing a specific fd |

### 4.3 State Flags (lib.rs ZygiskStateFlags)

| Flag | Value | Description | Visibility |
|------|-------|-------------|------------|
| `ProcessGrantedRoot` | `0x00000001` | App has root access | Module (public) |
| `ProcessOnDenyList` | `0x00000002` | App is denylisted | Module (public) |
| `DenyListEnforced` | `0x40000000` | DenyList enforcement active | Private (stripped) |
| `ProcessIsMagiskApp` | `0x80000000` | This is Magisk Manager | Private (stripped) |

### 4.4 Internal Flags (module.hpp)

| Flag | Value | Description |
|------|-------|-------------|
| `POST_SPECIALIZE` | `1 << 0` | After post-specialize completed |
| `APP_FORK_AND_SPECIALIZE` | `1 << 1` | Using fork+specialize path |
| `APP_SPECIALIZE` | `1 << 2` | Using specialize-only path |
| `SERVER_FORK_AND_SPECIALIZE` | `1 << 3` | System server path |
| `DO_REVERT_UNMOUNT` | `1 << 4` | Should revert magisk mounts |
| `SKIP_CLOSE_LOG_PIPE` | `1 << 5` | Don't close log pipe (specialize-only) |

---

## 5. Daemon IPC Protocol (Magisk)

### 5.1 Transport

- **Mechanism**: Unix socket via `connect_daemon(RequestCode::ZYGISK)`
- **Underlying**: `magiskd`'s main listener socket
- **Protocol**: Synchronous binary (C++ `xxread`/`xwrite` helpers)

### 5.2 Message Flow

```
Loader (Zygote child)                    magiskd
        │                                      │
        │── connect_daemon(ZYGISK) ──────────►│
        │── write_int(ZygiskRequest) ────────►│
        │                                      │
        │  [GetInfo]                           │
        │── write_int(uid) ──────────────────►│
        │── write_string(process) ───────────►│
        │── write_any<bool>(is_64_bit) ─────►│
        │◄──── write_pod(flags) ─────────────│
        │◄──── send_fds(module_fds[]) ────────│
        │                                      │
        │  [ConnectCompanion]                  │
        │── write_any<bool>(is_64_bit) ─────►│
        │◄──── send_fd(companion_socket) ────│
        │                                      │
        │  [GetModDir]                         │
        │── write_int(module_id) ────────────►│
        │◄──── send_fd(module_dir) ───────────│
```

### 5.3 Request Codes (lib.rs ZygiskRequest)

| Code | Name | Direction | Payload | Response |
|------|------|-----------|---------|----------|
| 0 | `GetInfo` | loader→daemon | uid, process, is_64_bit | flags, module_fds[] |
| 1 | `ConnectCompanion` | loader→daemon | is_64_bit | companion_socket_fd |
| 2 | `GetModDir` | loader→daemon | module_id | module_dir_fd |

### 5.4 Flag Computation (daemon.rs `get_process_info`)

```
flags = 0
flags |= ProcessOnDenyList    if is_deny_target(uid, process)   [deny/utils.cpp]
flags |= DenyListEnforced     if denylist_enforced               [deny/utils.cpp]
flags |= ProcessIsMagiskApp   if get_manager_uid() == uid       [daemon.rs]
flags |= ProcessGrantedRoot   if uid_granted_root(uid)          [daemon.rs]
```

---

## 6. OniMask Patch Inventory

### 6.1 Files Modified (vs upstream Magisk)

| File | Lines (upstream → patched) | Delta | Changes |
|------|---------------------------|-------|---------|
| `hook.cpp` | 627 → ~1030 | +~400 | All OniMask patches |

### 6.2 New Globals Added

| Global | Type | Purpose | Location |
|--------|------|---------|----------|
| `zygisk_hide_active` | `bool` | Master enable for all 3 phases | L208 |
| `orig_dl_iterate_phdr_runtime` | `fn ptr` | Real dl_iterate_phdr (libandroid_runtime backup) | L255 |
| `orig_dl_iterate_phdr_art` | `fn ptr` | Real dl_iterate_phdr (libart backup) | L256 |
| `g_art_dev` | `dev_t` | libart.so device number | L275 |
| `g_art_inode` | `ino_t` | libart.so inode number | L276 |
| `chained_openat` | `fn ptr` | Module's openat hook (if pre-registered) | L279 |
| `chained_readlink` | `fn ptr` | Module's readlink hook (if pre-registered) | L280 |
| `chained_dl_iterate_phdr_art` | `fn ptr` | Module's dl_iterate_phdr hook (if pre-registered) | L281 |
| `orig_openat` | `fn ptr` | Real openat (libart backup) | L332 |
| `orig_readlink` | `fn ptr` | Real readlink (libart backup) | L481 |

### 6.3 New Functions Added

| Function | Lines | Purpose |
|----------|-------|---------|
| `phdr_filter_callback()` | ~10 | Phase 1: callback to filter libzygisk.so from dl_phdr_info |
| `new_dl_iterate_phdr()` | ~15 | Phase 1: wrapper calling orig with filter |
| `is_proc_maps_path()` | ~10 | Phase 2: fast path validation for /proc/*/maps |
| `is_zygisk_maps_line()` | ~18 | Phase 2: substring search for ZYGISKLDR in maps line |
| `write_all()` | ~12 | Phase 2: interrupt-safe write loop |
| `new_openat()` | ~75 | Phase 2: maps sanitization via memfd |
| `do_openat()` | ~7 | Phase 2: chain-aware openat passthrough |
| `is_proc_fd_path()` | ~6 | Phase 3: validate /proc/*/fd/* path |
| `new_readlink()` | ~30 | Phase 3: fd symlink redirection to /dev/null |
| `do_readlink()` | ~7 | Phase 3: chain-aware readlink passthrough |

### 6.4 Modified Functions

| Function | Change |
|----------|--------|
| `hook_plt()` | Added `zygisk_hide_active = true` and Phase 1 dl_iterate_phdr hook |
| `hook_unloader()` | Rewrote: manual lsplt::RegisterHook with module chain detection; added Phase 1 (libart), Phase 2, Phase 3 |
| `pthread_attr_destroy()` | Added `zygisk_hide_active = false` before `restore_plt_hook()` |
| `~ZygiskContext()` | Added `unsetenv("ZYGISK_ENABLED")` guarded by `ProcessIsMagiskApp` |
| Includes | Added `<limits.h>`, `<cstdarg>`, `<sys/syscall.h>` |

### 6.5 Module Hook Chain Protection (F2 Fix)

```
Timeline in child process:
  1. Module preAppSpecialize() → module calls pltHookRegister("openat") + pltHookCommit()
     → GOT[libart.so."openat"] = module_openat
  2. ~ZygiskContext() → hook_unloader()
     → dlsym(RTLD_DEFAULT, "openat") = real_openat_address
     → lsplt::RegisterHook() reads GOT: saved = module_openat
     → saved != real_openat → chained_openat = module_openat
     → orig_openat = module_openat
     → GOT[libart.so."openat"] = new_openat (OniMask)
  3. At runtime: openat() → new_openat → [filter maps] → do_openat()
     → chained_openat (module) → orig_openat (would be module's backup → real openat)
```

---

## 7. ReZygisk Architecture & Feature Map

### 7.1 ReZygisk PLT Hooks (loader/src/injector/hook.c)

| # | Symbol | Library | Purpose |
|---|--------|---------|---------|
| 1 | `fork` | libandroid_runtime.so | Intercept forks, preload modules |
| 2 | `strdup` | libandroid_runtime.so | Detect ZygoteInit → JNI hook setup |
| 3 | `property_get` | libandroid_runtime.so | Timing hook — wait for libart.so to load |
| 4 | `FileDescriptorInfo::ReopenOrDetach` | libandroid_runtime.so | Close inaccessible FDs instead of aborting |
| 5 | `pthread_attr_setstacksize` | libart.so | Self-unload via `[[clang::musttail]] munmap()` |

### 7.2 ReZygisk Detection Hiding Features

| Feature | Mechanism | File | Magisk Zygisk Equivalent |
|---------|-----------|------|------------------------|
| `/proc/self/maps` sanitization | Not directly hooked; modules loaded via CSOLoader (memfd) avoid maps entries | (implicit) | OniMask Phase 2: `new_openat` |
| `dl_iterate_phdr` filtering | Not hooked; CSOLoader avoids phdr entries | (implicit) | OniMask Phase 1: `new_dl_iterate_phdr` |
| `/proc/self/fd/*` readlink filtering | Not hooked | (none) | OniMask Phase 3: `new_readlink` |
| `/proc/self/status` TracerPid clearing | seccomp-BPF + ptrace message clearing | `ptrace_clear.c` | Not in Magisk |
| Mount namespace umount | `umount_root()` (Magisk/KSU/APatch) | `zygiskd/utils.c` | Magisk: `revert_unmount()` |
| FD sanitization | Close all non-allowed FDs after fork | `hook.c` rz_sanitize_fds | Magisk: `sanitize_fds()` |
| FileDescriptorInfo workaround | Close inaccessible FDs | `hook.c` new_ReopenOrDetach | Not in Magisk |
| Seccomp filter detection | Check `Seccomp_filters:` visibility; skip ptrace if detectable | `ptrace_clear.c` | Not in Magisk |
| Module memfd loading | CSOLoader maps ELF from fd, avoiding dlopen traces | (csoloader lib) | Magisk uses android_dlopen_ext |
| Self-unloading | `[[clang::musttail]] munmap()` — complete memory removal | `hook.c` | Magisk: `[[clang::musttail]] dlclose()` or munmap |
| Root multi-backend | Magisk + KernelSU + APatch detection | `root_impl/` | Magisk only |

### 7.3 ReZygisk Module API (v5)

```c
struct rezygisk_api {
    void *impl;
    bool (*register_module)(struct rezygisk_api *, struct rezygisk_abi const *);
    void (*hook_jni_native_methods)(JNIEnv *, const char *, JNINativeMethod *, int);
    void (*plt_hook_register_v4)(dev_t, ino_t, const char *, void *, void **);
    void (*exempt_fd)(int);
    bool (*plt_hook_commit)();
    int (*connect_companion)(void *);
    void (*set_option)(void *, enum rezygisk_options);
    int (*get_module_dir)(void *);
    uint32_t (*get_flags)();
};
```

### 7.4 ReZygisk Flags (beyond Magisk)

| Flag | Bit | Description |
|------|-----|-------------|
| `PROCESS_GRANTED_ROOT` | 0 | App has root |
| `PROCESS_ON_DENYLIST` | 1 | App is denylisted |
| `PROCESS_IS_MANAGER` | 27 | This is the root manager app |
| `PROCESS_ROOT_IS_APATCH` | 28 | Root impl is APatch |
| `PROCESS_ROOT_IS_KSU` | 29 | Root impl is KernelSU |
| `PROCESS_ROOT_IS_MAGISK` | 30 | Root impl is Magisk |

### 7.5 ReZygisk Daemon IPC (zygiskd)

Socket: `/data/adb/rezygisk/cp{32,64}.sock` (AF_UNIX, SOCK_STREAM)

| Action | Value | Request | Response |
|--------|-------|---------|----------|
| `ZygoteInjected` | 0 | — | — |
| `GetProcessFlags` | 1 | uid, process_name | flags |
| `GetInfo` | 2 | — | flags, pid, modules[] |
| `ReadModules` | 3 | — | count, lib_paths[] |
| `RequestCompanionSocket` | 4 | module_index | companion fd |
| `GetModuleDir` | 5 | module_index | dir fd |
| `ZygoteRestart` | 6 | — | close companions |
| `UpdateMountNamespace` | 7 | pid, mns_state | daemon_pid, ns_fd |
| `RemoveModule` | 8 | module_index | success/fail |

---

## 8. ReZygisk vs Magisk Zygisk — Detailed Diff

### 8.1 Injection Method

| Aspect | Magisk Zygisk | ReZygisk |
|--------|--------------|----------|
| Loading mechanism | `ro.dalvik.vm.native.bridge` property trick | Ptrace at AT_ENTRY + CSOLoader |
| Entry point | `NativeBridgeItf::isCompatibleWith` | `entry(base_addr, size, tango)` |
| Library format | Standard `.so` loaded by linker | Standard `.so` loaded by custom CSOLoader |
| Tracer required | No (native bridge trick) | Yes (monitor traces init, ptracer injects Zygote) |
| Init tracing | Via magiskd init support | Dedicated monitor process |

### 8.2 Hook Architecture

| Aspect | Magisk Zygisk | ReZygisk |
|--------|--------------|----------|
| PLT hook library | libandroid_runtime.so + libart.so | libandroid_runtime.so + libart.so |
| Fork hook | `fork` in libandroid_runtime.so | `fork` in libandroid_runtime.so |
| Unload trigger | `pthread_attr_destroy` in libart.so | `pthread_attr_setstacksize` in libart.so |
| Unload method | `[[clang::musttail]] dlclose(self_handle)` | `[[clang::musttail]] munmap(start, size)` |
| JNI hook count | 21 variants (12+7+2) | 21 variants (12+6+3) |
| JNI hook method | `RegisterNatives` via `NativeBridgeRuntimeCallbacks` | `RegisterNatives` via `JNI_GetCreatedJavaVMs` + ART method manipulation |
| Detection hiding | None (upstream); OniMask adds 3 phases | ptrace message clearing + CSOLoader (implicit) |

### 8.3 Detection Vectors

| Vector | Magisk Zygisk | ReZygisk | OniMask |
|--------|--------------|----------|---------|
| `/proc/self/maps` | Visible | Hidden via CSOLoader | **Phase 2: memfd filtering** |
| `dl_iterate_phdr` | Visible | Hidden via CSOLoader | **Phase 1: phdr callback filter** |
| `/proc/self/fd/*` readlink | Visible | Visible | **Phase 3: /dev/null redirect** |
| `/proc/self/status` TracerPid | Visible | **Hidden** (seccomp ptrace clear) | Not hidden |
| `/proc/self/maps` module libs | Visible | Hidden via CSOLoader | Hidden (OniMask filters all ZYGISKLDR) |
| Environment variables | `ZYGISK_ENABLED` visible | Not set | Cleared (guarded for Magisk app) |
| PLT hook artifacts | `lsplt` leaves no trace | `lsplt` + CSOLoader | `lsplt` leaves no trace |

---

## 9. Feature Porting Guide — ReZygisk → OniMask

### 9.1 Priority 1: High-Impact Detection Hiding

#### 9.1.1 Ptrace Message Clearing (TracerPid)

**ReZygisk source**: `loader/src/injector/ptrace_clear.c` (106 lines)

**What it does**: Clears `TracerPid` from `/proc/self/status` by exploiting a seccomp-BPF + ptrace interaction that erases the ptrace relationship in the kernel.

**Porting complexity**: HIGH — requires ptrace infrastructure that Magisk doesn't have in Zygote child processes.

**Prerequisite**: OniMask would need a ptrace monitor (like ReZygisk's `monitor.c`) or a different mechanism.

**Alternative approach**: Use `prctl(PR_SET_DUMPABLE, 0)` or `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` — but these don't actually clear TracerPid.

**Recommendation**: Defer until ptrace infrastructure is available. Document as future enhancement.

#### 9.1.2 Environment Variable Hiding

**ReZygisk behavior**: ReZygisk doesn't set `ZYGISK_ENABLED` at all.

**OniMask current**: Sets `ZYGISK_ENABLED=1` for Magisk app only; clears it for all other apps via `unsetenv`.

**Porting complexity**: ALREADY DONE — OniMask handles this.

**File**: `hook.cpp` `~ZygiskContext()` L510, `module.cpp` L415.

#### 9.1.3 Enhanced Maps Sanitization

**ReZygisk approach**: Avoids maps entries entirely by loading modules via CSOLoader (memfd). No maps filtering needed.

**OniMask approach**: Filters maps content at read time via `new_openat`.

**Improvement opportunity**: ReZygisk's CSOLoader approach is more robust because it avoids maps entries at the source. However, it requires replacing `android_dlopen_ext` with a custom ELF loader.

**Recommendation**: Current memfd approach is sufficient. CSOLoader porting is a major refactor.

### 9.2 Priority 2: Stability & Compatibility

#### 9.2.1 FileDescriptorInfo::ReopenOrDetach Hook

**ReZygisk source**: `loader/src/injector/hook.c` line 285

**What it does**: Zygote aborts when it can't verify FDs after fork (if overlay files are inaccessible after umount). This hook intercepts the verification and closes inaccessible FDs instead of aborting.

**Porting complexity**: MEDIUM — requires prefix-matching PLT hook registration (ReZygisk uses `PLT_HOOK_REGISTER_SYM` with partial symbol match).

**Integration point**: `hook_plt()` in `hook.cpp`, after existing hooks.

**Key code** (ReZygisk hook.c L285-330):
```c
// Hook FileDescriptorInfo::ReopenOrDetach (prefix match)
// Called by Zygote to verify FDs before fork
// After umount, overlay files don't exist → Zygote would abort
// Solution: close the FD instead of verifying
```

#### 9.2.2 Companion Crash Recovery

**ReZygisk source**: `zygiskd/src/zygiskd.c` `check_unix_socket()`

**What it does**: Detects crashed companion processes by testing socket connectivity, and respawns them on demand.

**Magisk equivalent**: Magisk creates companions on-demand via `connect_zygiskd()` in `daemon.rs`. No crash recovery.

**Porting complexity**: MEDIUM — requires modifications to `daemon.rs` companion management.

#### 9.2.3 Root Multi-Backend Support

**ReZygisk source**: `zygiskd/src/root_impl/` (magisk.c, kernelsu.c, apatch.c)

**What it does**: Detects which root solution is active (Magisk, KernelSU, APatch) and queries the appropriate backend for denylist/grant information.

**Porting complexity**: HIGH — requires significant daemon-side changes. OniMask is a Magisk-only patch.

**Recommendation**: Not applicable for OniMask's Magisk-only scope.

### 9.3 Priority 3: Enhanced API Features

#### 9.3.1 Extended State Flags

**ReZygisk flags not in Magisk**:
- `PROCESS_ROOT_IS_APATCH` (bit 28)
- `PROCESS_ROOT_IS_KSU` (bit 29)
- `PROCESS_ROOT_IS_MAGISK` (bit 30)

**Porting approach**: Add to `ZygiskStateFlags` in `lib.rs` and `module.hpp`. Compute in `get_process_info()` in `daemon.rs`.

**Integration points**:
- `native/src/core/lib.rs` L121 — add enum variants
- `native/src/core/zygisk/daemon.rs` L191 — compute in `get_process_info()`
- `native/src/core/zygisk/module.hpp` L128 — add static_assert if exposing to modules

#### 9.3.2 PLT Hook Exclusion (v3 API)

**ReZygisk**: Modules can call `pltHookExclude(regex, symbol)` to prevent hooking specific libraries.

**Magisk v1-v3**: Same API exists via `plt_hook_exclude()` in `module.cpp` L174.

**Magisk v4**: Removed in favor of direct `pltHookRegister(dev, inode, ...)`.

**Porting**: Already available in Magisk's v1-v3 API path.

### 9.4 Integration Map — Quick Reference

| ReZygisk Feature | Port to OniMask | Files to Modify | Effort |
|-----------------|-----------------|------------------|--------|
| TracerPid clearing | ⏳ Future | New ptrace infra | HIGH |
| FileDescriptorInfo hook | ✅ Recommended | `hook.cpp` | MEDIUM |
| Companion crash recovery | ⏳ Optional | `daemon.rs` | MEDIUM |
| Extended flags (KSU/APatch) | ❌ N/A (Magisk only) | — | — |
| CSOLoader module loading | ⏳ Major refactor | New loader subsystem | VERY HIGH |
| WebUI module management | ❌ N/A (out of scope) | — | — |
| Enhanced JNI variants | ✅ Already covered | `jni_hooks.hpp` | DONE |
| Mount ns caching | ✅ Already in Magisk | `mount.rs` | DONE |

---

## 10. File Cross-Reference

### 10.1 Magisk Zygisk Source Map

| File | Path | Purpose |
|------|------|---------|
| `hook.cpp` | `native/src/core/zygisk/hook.cpp` | **All PLT hooks, lifecycle, bootstrap** |
| `module.cpp` | `native/src/core/zygisk/module.cpp` | Module loading, API impl, FD sanitization |
| `module.hpp` | `native/src/core/zygisk/module.hpp` | Module structs, ZygiskContext, API table |
| `entry.cpp` | `native/src/core/zygisk/entry.cpp` | Injection entry, companion daemon, NativeBridgeItf |
| `zygisk.hpp` | `native/src/core/zygisk/zygisk.hpp` | Constants (ZYGISKLDR, NBPROP), logging macros |
| `api.hpp` | `native/src/core/zygisk/api.hpp` | Public module API (zygisk namespace) |
| `jni_hooks.hpp` | `native/src/core/zygisk/jni_hooks.hpp` | Auto-generated JNI hook wrappers |
| `daemon.rs` | `native/src/core/zygisk/daemon.rs` | Daemon IPC, ZygiskState, process info |
| `mod.rs` | `native/src/core/zygisk/mod.rs` | Companion entry, exec_companion_entry |
| `lib.rs` | `native/src/core/lib.rs` | FFI bridge (Cxx), enums, type definitions |
| `core.hpp` | `native/src/core/include/core.hpp` | C++ API declarations, denylist, scripting |
| `deny/utils.cpp` | `native/src/core/deny/utils.cpp` | Denylist data structures, `update_deny_flags()` |
| `mount.rs` | `native/src/core/mount.rs` | `revert_unmount()`, mount namespace management |

### 10.2 ReZygisk Source Map

| File | Path | Purpose |
|------|------|---------|
| `hook.c` | `loader/src/injector/hook.c` | **All PLT hooks, JNI hooks, module lifecycle** |
| `hook.h` | `loader/src/injector/hook.h` | Hook struct definitions |
| `module.h` | `loader/src/injector/module.h` | Module API v1-v5, app_specialize_args |
| `entry.c` | `loader/src/injector/entry.c` | Injection entry point |
| `jni_hooks.h` | `loader/src/injector/jni_hooks.h` | Auto-generated JNI hook wrappers (21 variants) |
| `art_method.h` | `loader/src/injector/art_method.h` | ART method manipulation for JNI hooks |
| `ptrace_clear.c` | `loader/src/injector/ptrace_clear.c` | Ptrace message clearing (TracerPid) |
| `ptracer.c` | `loader/src/ptracer/ptracer.c` | Ptrace injection, AT_ENTRY, remote calls |
| `monitor.c` | `loader/src/ptracer/monitor.c` | Init process tracer |
| `zygiskd.c` | `zygiskd/src/zygiskd.c` | Daemon main loop, module loading |
| `companion.c` | `zygiskd/src/companion.c` | Companion process per module |
| `utils.c` | `zygiskd/src/utils.c` | Mount ns management, umount, SELinux |
| `constants.h` | `zygiskd/src/constants.h` | ProcessFlags, DaemonSocketAction enums |
| `daemon.c` | `loader/src/common/daemon.c` | IPC client implementation |
