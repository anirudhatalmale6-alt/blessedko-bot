#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include <cstdio>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks v8 - Indirect Call-Site Hooking
//
// v7 scan found the game uses INDIRECT calls for send/recv:
//   0x004A5C13: MOV ESI, [0x00C53610]  ; load send ptr into ESI
//               ... CALL ESI            ; call send through register
//   0x004A6E44: MOV EBX, [0x00C53620]  ; load recv ptr into EBX
//               ... CALL EBX            ; call recv through register
//
// v8 Patch: Replace MOV reg, [IAT_addr] with MOV reg, hookAddr
//   Original (6 bytes): 8B 35 10 36 C5 00  = MOV ESI, [0x00C53610]
//   Patched  (6 bytes): BE [hkSend addr] 90 = MOV ESI, hkSend; NOP
//
// The register gets loaded with OUR function instead of real send.
// When game does CALL ESI, it calls our hook. Our hook calls real
// send/recv directly (unmodified system functions).
//
// Nothing modified: IAT entries, wsock32 bytes, ws2_32 bytes.
// Only 6 bytes changed in game code at each site.
// ============================================================

namespace Hooks {

    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    // Real function pointers (saved from IAT before patching)
    inline tSend realSend = nullptr;
    inline tRecv realRecv = nullptr;

    inline volatile SOCKET gameSocket = INVALID_SOCKET;

    // Patched sites tracking
    struct PatchSite {
        DWORD address;
        uint8_t origBytes[6];
        uint8_t reg;          // Register number (0=EAX..7=EDI)
        bool isSend;          // true=send, false=recv
    };
    inline std::vector<PatchSite> patchedSites;

    // Hook counters
    inline volatile LONG sendHookCount = 0;
    inline volatile LONG recvHookCount = 0;

    // Debug
    inline FILE* logFile = nullptr;
    inline char debugInfo[4096] = {};
    inline int debugPos = 0;
    inline HANDLE hHookLog = INVALID_HANDLE_VALUE;

    inline void RawLog(const char* msg) {
        if (hHookLog == INVALID_HANDLE_VALUE) {
            hHookLog = CreateFileA("BlessedBot_hook.log",
                GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
        if (hHookLog != INVALID_HANDLE_VALUE) {
            DWORD written;
            DWORD len = 0;
            const char* p = msg;
            while (*p++) len++;
            WriteFile(hHookLog, msg, len, &written, nullptr);
            FlushFileBuffers(hHookLog);
        }
    }

    inline void RawLogHex(const char* prefix, DWORD value) {
        char buf[80];
        const char* hex = "0123456789ABCDEF";
        int pos = 0;
        const char* p = prefix;
        while (*p && pos < 60) buf[pos++] = *p++;
        buf[pos++] = '0'; buf[pos++] = 'x';
        for (int i = 7; i >= 0; i--)
            buf[pos++] = hex[(value >> (i * 4)) & 0xF];
        buf[pos++] = '\n';
        buf[pos] = 0;
        RawLog(buf);
    }

    inline void LogToFile(const char* fmt, ...) {
        if (!logFile) fopen_s(&logFile, "BlessedBot_debug.log", "a");
        if (logFile) {
            va_list args;
            va_start(args, fmt);
            vfprintf(logFile, fmt, args);
            va_end(args);
            fflush(logFile);
        }
    }

    inline void DbgLog(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        int written = vsnprintf(debugInfo + debugPos, sizeof(debugInfo) - debugPos, fmt, args);
        va_end(args);
        if (written > 0) debugPos += written;
        va_start(args, fmt);
        LogToFile("[HOOK] ");
        if (logFile) { vfprintf(logFile, fmt, args); fflush(logFile); }
        va_end(args);
    }

    // Packet log
    struct PacketLog {
        bool     isSend;
        DWORD    timestamp;
        std::vector<uint8_t> data;
    };

    inline std::vector<PacketLog> packetLog;
    inline std::mutex logMutex;
    constexpr size_t MAX_LOG_SIZE = 1000;

    using PacketCallback = std::function<bool(bool isSend, const uint8_t* data, int len)>;
    inline PacketCallback onPacket = nullptr;

    inline int SendGamePacket(const uint8_t* data, int len) {
        if (realSend && gameSocket != INVALID_SOCKET)
            return realSend(gameSocket, (const char*)data, len, 0);
        return -1;
    }

    // ================================================================
    // HOOK FUNCTIONS
    // Called via register (CALL ESI / CALL EBX) after our patch.
    // Must be __stdcall to match original send/recv calling convention.
    // ================================================================

    __declspec(noinline) static int __stdcall hkSend(SOCKET s, const char* buf, int len, int flags) {
        LONG count = InterlockedIncrement(&sendHookCount);

        if (gameSocket == INVALID_SOCKET)
            gameSocket = s;

        if (count == 1) {
            RawLog("=== hkSend ENTERED (first call) ===\n");
            RawLogHex("  socket: ", (DWORD)s);
            RawLogHex("  len: ", (DWORD)len);
            RawLogHex("  realSend: ", (DWORD)realSend);
        }

        // Log packet
        {
            std::lock_guard<std::mutex> lock(logMutex);
            PacketLog entry;
            entry.isSend = true;
            entry.timestamp = GetTickCount();
            if (len > 0 && buf)
                entry.data.assign((uint8_t*)buf, (uint8_t*)buf + len);
            packetLog.push_back(entry);
            if (packetLog.size() > MAX_LOG_SIZE)
                packetLog.erase(packetLog.begin());
        }

        if (onPacket) {
            bool allow = onPacket(true, (const uint8_t*)buf, len);
            if (!allow) return len;
        }

        // Call REAL send (completely unmodified system function!)
        return realSend(s, buf, len, flags);
    }

    __declspec(noinline) static int __stdcall hkRecv(SOCKET s, char* buf, int len, int flags) {
        LONG count = InterlockedIncrement(&recvHookCount);

        if (count == 1) {
            RawLog("=== hkRecv ENTERED (first call) ===\n");
            RawLogHex("  socket: ", (DWORD)s);
            RawLogHex("  len: ", (DWORD)len);
            RawLogHex("  realRecv: ", (DWORD)realRecv);
        }

        // Call REAL recv (completely unmodified!)
        int result = realRecv(s, buf, len, flags);

        if (result > 0) {
            {
                std::lock_guard<std::mutex> lock(logMutex);
                PacketLog entry;
                entry.isSend = false;
                entry.timestamp = GetTickCount();
                entry.data.assign((uint8_t*)buf, (uint8_t*)buf + result);
                packetLog.push_back(entry);
                if (packetLog.size() > MAX_LOG_SIZE)
                    packetLog.erase(packetLog.begin());
            }

            if (onPacket) {
                onPacket(false, (const uint8_t*)buf, result);
            }
        }

        return result;
    }

    // ================================================================
    // INDIRECT CALL-SITE SCANNER & PATCHER
    // ================================================================

    // Register names for logging
    inline const char* RegName(uint8_t reg) {
        const char* names[] = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };
        return reg < 8 ? names[reg] : "???";
    }

    // Scan for MOV r32, [iatAddr] patterns and patch them
    inline int ScanAndPatchIndirect(DWORD startAddr, DWORD size,
        DWORD iatAddr, DWORD hookAddr, bool isSend, const char* name) {

        uint8_t* base = (uint8_t*)startAddr;
        int count = 0;

        for (DWORD i = 0; i + 6 <= size; i++) {
            bool found = false;
            uint8_t reg = 0;
            int instrLen = 0;

            // Pattern 1: A1 [iatAddr] = MOV EAX, [addr] (5 bytes)
            if (base[i] == 0xA1 && *(DWORD*)(base + i + 1) == iatAddr) {
                found = true;
                reg = 0; // EAX
                instrLen = 5;
            }
            // Pattern 2: 8B xx [iatAddr] = MOV r32, [addr] (6 bytes)
            // ModR/M byte: mod=00, reg=r, r/m=101 (disp32)
            // So byte & 0xC7 must equal 0x05
            else if (base[i] == 0x8B && (base[i + 1] & 0xC7) == 0x05
                && *(DWORD*)(base + i + 2) == iatAddr) {
                found = true;
                reg = (base[i + 1] >> 3) & 7;
                instrLen = 6;
            }

            if (!found) continue;

            DWORD addr = startAddr + i;
            DbgLog("  %s: MOV %s, [0x%08X] at 0x%08X (%d bytes)\n",
                name, RegName(reg), iatAddr, addr, instrLen);

            // Backup original bytes
            PatchSite site;
            site.address = addr;
            memcpy(site.origBytes, base + i, 6);
            site.reg = reg;
            site.isSend = isSend;

            // Patch: MOV reg, imm32 = (0xB8 + reg) [4-byte imm]
            // This is 5 bytes. If original was 6 bytes, add NOP.
            // If original was 5 bytes (A1), exact fit.
            DWORD oldProt;
            if (!VirtualProtect(base + i, 6, PAGE_EXECUTE_READWRITE, &oldProt)) {
                DbgLog("    FAILED: VirtualProtect error %d\n", GetLastError());
                continue;
            }

            base[i] = 0xB8 + reg;           // MOV reg, imm32
            *(DWORD*)(base + i + 1) = hookAddr;
            if (instrLen == 6)
                base[i + 5] = 0x90;          // NOP for 6-byte instructions

            VirtualProtect(base + i, 6, oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), base + i, 6);

            // Log patched bytes
            DbgLog("    Patched: %02X %02X %02X %02X %02X %02X (MOV %s, 0x%08X)\n",
                base[i], base[i + 1], base[i + 2], base[i + 3], base[i + 4], base[i + 5],
                RegName(reg), hookAddr);

            patchedSites.push_back(site);
            count++;
        }

        return count;
    }

    // ---- Install Hooks ----
    inline bool InstallNetworkHooks() {
        debugPos = 0;
        memset(debugInfo, 0, sizeof(debugInfo));

        DbgLog("=== Hook Install v8 (Indirect Call-Site) ===\n");
        DbgLog("Patch MOV reg,[IAT] to MOV reg,hookAddr\n\n");

        // Step 1: Save real function pointers from IAT
        DWORD iatSendPtr = *(DWORD*)KO::IAT::WS_SEND;
        DWORD iatRecvPtr = *(DWORD*)KO::IAT::WS_RECV;

        realSend = (tSend)iatSendPtr;
        realRecv = (tRecv)iatRecvPtr;

        DbgLog("IAT send [0x%08X] -> 0x%08X\n", KO::IAT::WS_SEND, iatSendPtr);
        DbgLog("IAT recv [0x%08X] -> 0x%08X\n", KO::IAT::WS_RECV, iatRecvPtr);

        // Verify real functions are untouched
        uint8_t* sb = (uint8_t*)iatSendPtr;
        uint8_t* rb = (uint8_t*)iatRecvPtr;
        DbgLog("send bytes: %02X %02X %02X %02X %02X (8B FF 55 8B EC = OK)\n",
            sb[0], sb[1], sb[2], sb[3], sb[4]);
        DbgLog("recv bytes: %02X %02X %02X %02X %02X (8B FF 55 8B EC = OK)\n",
            rb[0], rb[1], rb[2], rb[3], rb[4]);

        DWORD hookSendAddr = (DWORD)&hkSend;
        DWORD hookRecvAddr = (DWORD)&hkRecv;
        DbgLog("hkSend: 0x%08X\n", hookSendAddr);
        DbgLog("hkRecv: 0x%08X\n", hookRecvAddr);

        // Step 2: Get game module sections
        HMODULE hGame = GetModuleHandleA(nullptr);
        if (!hGame) {
            DbgLog("FAIL: Cannot get game module\n");
            return false;
        }

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hGame;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hGame + dos->e_lfanew);
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        WORD numSections = nt->FileHeader.NumberOfSections;

        // Step 3: Scan all readable sections for MOV reg, [IAT_send/recv]
        DbgLog("\nScanning for MOV reg, [IAT_send/recv]...\n");

        int totalSend = 0, totalRecv = 0;

        for (WORD i = 0; i < numSections; i++) {
            DWORD secStart = (DWORD)hGame + sections[i].VirtualAddress;
            DWORD secSize = sections[i].Misc.VirtualSize;
            if (!(sections[i].Characteristics & IMAGE_SCN_MEM_READ)) continue;

            char secName[9] = {};
            memcpy(secName, sections[i].Name, 8);

            totalSend += ScanAndPatchIndirect(secStart, secSize,
                KO::IAT::WS_SEND, hookSendAddr, true, "send");
            totalRecv += ScanAndPatchIndirect(secStart, secSize,
                KO::IAT::WS_RECV, hookRecvAddr, false, "recv");
        }

        DbgLog("\n=== Results ===\n");
        DbgLog("Send MOV patches: %d\n", totalSend);
        DbgLog("Recv MOV patches: %d\n", totalRecv);
        DbgLog("wsock32/ws2_32 bytes modified: ZERO\n");
        DbgLog("IAT entries modified: ZERO\n");
        DbgLog("Game code bytes modified: %d (send) + %d (recv) = %d total\n",
            totalSend * 6, totalRecv * 6, (totalSend + totalRecv) * 6);

        if (totalSend == 0 && totalRecv == 0) {
            DbgLog("\nFAIL: No indirect call sites found!\n");
            return false;
        }

        // Pre-activate runtime log
        RawLog("=== v8 Hook Runtime Log ===\n");
        RawLogHex("Send patches: ", (DWORD)totalSend);
        RawLogHex("Recv patches: ", (DWORD)totalRecv);
        RawLogHex("realSend: ", (DWORD)realSend);
        RawLogHex("realRecv: ", (DWORD)realRecv);
        RawLog("Hooks ACTIVE - waiting for first packet...\n");

        DbgLog("\n=== Hook Install Complete (v8) ===\n");
        return true;
    }

    // ---- Remove Hooks ----
    inline void RemoveNetworkHooks() {
        for (auto& site : patchedSites) {
            uint8_t* p = (uint8_t*)site.address;
            DWORD oldProt;
            if (VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldProt)) {
                memcpy(p, site.origBytes, 6);
                VirtualProtect(p, 6, oldProt, &oldProt);
                FlushInstructionCache(GetCurrentProcess(), p, 6);
            }
        }
        patchedSites.clear();
        realSend = nullptr;
        realRecv = nullptr;
        if (logFile) { fclose(logFile); logFile = nullptr; }
        if (hHookLog != INVALID_HANDLE_VALUE) { CloseHandle(hHookLog); hHookLog = INVALID_HANDLE_VALUE; }
    }

    // ---- Get hook stats ----
    inline void GetHookStats(char* buf, int bufSize) {
        sprintf_s(buf, bufSize,
            "Patches: %zu sites | Calls: send=%ld recv=%ld",
            patchedSites.size(), sendHookCount, recvHookCount);
    }

    // ---- IAT Hook Helper (for DefenderBypass) ----
    inline bool PatchIAT(HMODULE hModule, const char* dllName, const char* funcName, DWORD newFunc, DWORD* oldFunc) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)(
            (DWORD)hModule + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        for (; imports->Name; imports++) {
            const char* name = (const char*)((DWORD)hModule + imports->Name);
            if (_stricmp(name, dllName) != 0) continue;

            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((DWORD)hModule + imports->OriginalFirstThunk);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD)hModule + imports->FirstThunk);

            for (; origThunk->u1.AddressOfData; origThunk++, thunk++) {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((DWORD)hModule + origThunk->u1.AddressOfData);
                if (strcmp((const char*)import->Name, funcName) == 0) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
                    *oldFunc = thunk->u1.Function;
                    thunk->u1.Function = newFunc;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD), oldProtect, &oldProtect);
                    return true;
                }
            }
        }
        return false;
    }

} // namespace Hooks
