#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include <cstdio>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks v7 - Call-Site Hooking
//
// v6 Mode 0 (NAKED passthrough, literally one JMP instruction)
// STILL crashed. This proves KODefender has a function-byte
// integrity check on wsock32/ws2_32 send/recv.
//
// v7 Solution: DON'T modify system DLL bytes at all!
// Instead, find the game's CALL DWORD PTR [IAT_send] instructions
// in KnightOnLine.exe and redirect THOSE to our hooks.
//
// The game code does: CALL DWORD PTR [0x00C53610]  (FF 15 10 36 C5 00)
// We replace with:    CALL our_hkSend; NOP         (E8 xx xx xx xx 90)
//
// KODefender checks:
//   - IAT entries (v1 "Cheat Detected")
//   - Function bytes of send/recv (v2-v6 silent crash)
//   - But NOT every CALL instruction in the game code!
//
// Our hook calls real send/recv directly (they're UNMODIFIED).
// ============================================================

namespace Hooks {

    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    // Real function pointers (read from IAT before any modification)
    inline tSend realSend = nullptr;
    inline tRecv realRecv = nullptr;

    inline volatile SOCKET gameSocket = INVALID_SOCKET;

    // Call site tracking
    struct CallSite {
        DWORD address;        // Address of the CALL instruction
        uint8_t origBytes[6]; // Original 6 bytes (FF 15 xx xx xx xx)
    };
    inline std::vector<CallSite> sendCallSites;
    inline std::vector<CallSite> recvCallSites;

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
    // These are proper __stdcall functions called from patched CALL sites.
    // They call the REAL send/recv (unmodified system functions).
    // ================================================================

    __declspec(noinline) static int __stdcall hkSend(SOCKET s, const char* buf, int len, int flags) {
        LONG count = InterlockedIncrement(&sendHookCount);

        if (gameSocket == INVALID_SOCKET)
            gameSocket = s;

        // Log first call
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

        // Call REAL send (unmodified function!)
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

        // Call REAL recv (unmodified function!)
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
    // CALL-SITE SCANNER & PATCHER
    // Finds CALL DWORD PTR [IAT_addr] instructions in game code
    // and replaces them with CALL our_hook + NOP
    // ================================================================

    // Scan a memory range for a 6-byte pattern: FF 15 [4-byte LE addr]
    inline std::vector<DWORD> FindCallSites(DWORD startAddr, DWORD size, DWORD iatAddr) {
        std::vector<DWORD> results;
        uint8_t pattern[6];
        pattern[0] = 0xFF;
        pattern[1] = 0x15;
        *(DWORD*)(pattern + 2) = iatAddr;

        uint8_t* base = (uint8_t*)startAddr;
        for (DWORD i = 0; i + 6 <= size; i++) {
            if (memcmp(base + i, pattern, 6) == 0) {
                results.push_back(startAddr + i);
            }
        }
        return results;
    }

    // Patch a CALL site: replace FF 15 xx xx xx xx with E8 rel32 90
    inline bool PatchCallSite(DWORD callAddr, DWORD hookFunc, uint8_t* backupBytes) {
        uint8_t* p = (uint8_t*)callAddr;

        // Backup original 6 bytes
        memcpy(backupBytes, p, 6);

        // Calculate relative offset for E8 CALL
        // E8 is 5 bytes, relative offset is from end of instruction (callAddr + 5)
        int32_t rel = (int32_t)(hookFunc - (callAddr + 5));

        DWORD oldProt;
        if (!VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;

        p[0] = 0xE8;                  // CALL rel32
        *(int32_t*)(p + 1) = rel;     // relative offset
        p[5] = 0x90;                  // NOP (fill remaining byte)

        VirtualProtect(p, 6, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), p, 6);

        return true;
    }

    // Restore a patched CALL site
    inline bool RestoreCallSite(DWORD callAddr, uint8_t* origBytes) {
        uint8_t* p = (uint8_t*)callAddr;
        DWORD oldProt;
        if (!VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;
        memcpy(p, origBytes, 6);
        VirtualProtect(p, 6, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), p, 6);
        return true;
    }

    // ---- Install Hooks ----
    inline bool InstallNetworkHooks() {
        debugPos = 0;
        memset(debugInfo, 0, sizeof(debugInfo));

        DbgLog("=== Hook Install v7 (Call-Site Hooking) ===\n");
        DbgLog("Strategy: Patch game's CALL instructions, NOT system DLL bytes\n\n");

        // Step 1: Get real function pointers from IAT
        DWORD iatSendPtr = *(DWORD*)KO::IAT::WS_SEND;
        DWORD iatRecvPtr = *(DWORD*)KO::IAT::WS_RECV;

        realSend = (tSend)iatSendPtr;
        realRecv = (tRecv)iatRecvPtr;

        DbgLog("IAT send entry at 0x%08X -> 0x%08X\n", KO::IAT::WS_SEND, iatSendPtr);
        DbgLog("IAT recv entry at 0x%08X -> 0x%08X\n", KO::IAT::WS_RECV, iatRecvPtr);
        DbgLog("realSend = 0x%08X\n", (DWORD)realSend);
        DbgLog("realRecv = 0x%08X\n", (DWORD)realRecv);

        // Verify real functions are intact (should start with 8B FF)
        char hexBuf[64];
        uint8_t* sendBytes = (uint8_t*)iatSendPtr;
        uint8_t* recvBytes = (uint8_t*)iatRecvPtr;
        sprintf_s(hexBuf, "%02X %02X %02X %02X %02X",
            sendBytes[0], sendBytes[1], sendBytes[2], sendBytes[3], sendBytes[4]);
        DbgLog("send function bytes: %s (should be 8B FF 55 8B EC)\n", hexBuf);
        sprintf_s(hexBuf, "%02X %02X %02X %02X %02X",
            recvBytes[0], recvBytes[1], recvBytes[2], recvBytes[3], recvBytes[4]);
        DbgLog("recv function bytes: %s (should be 8B FF 55 8B EC)\n", hexBuf);

        // Step 2: Get KnightOnLine.exe module info
        HMODULE hGame = GetModuleHandleA(nullptr);
        if (!hGame) {
            DbgLog("FAIL: Cannot get game module\n");
            return false;
        }

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hGame;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hGame + dos->e_lfanew);
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        WORD numSections = nt->FileHeader.NumberOfSections;

        DbgLog("Game module: 0x%08X, %d sections\n", (DWORD)hGame, numSections);

        // Step 3: Scan ALL executable sections for CALL [IAT_send] and CALL [IAT_recv]
        DWORD hookSendAddr = (DWORD)&hkSend;
        DWORD hookRecvAddr = (DWORD)&hkRecv;
        DbgLog("hkSend at: 0x%08X\n", hookSendAddr);
        DbgLog("hkRecv at: 0x%08X\n", hookRecvAddr);

        int totalSendSites = 0;
        int totalRecvSites = 0;

        DbgLog("\nScanning sections for CALL [IAT] patterns...\n");

        for (WORD i = 0; i < numSections; i++) {
            DWORD secStart = (DWORD)hGame + sections[i].VirtualAddress;
            DWORD secSize = sections[i].Misc.VirtualSize;
            DWORD secChars = sections[i].Characteristics;
            char secName[9] = {};
            memcpy(secName, sections[i].Name, 8);

            // Only scan sections that contain code or are readable
            bool isCode = (secChars & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isReadable = (secChars & IMAGE_SCN_MEM_READ) != 0;

            DbgLog("  Section '%s': 0x%08X size=0x%X [%s%s]\n",
                secName, secStart, secSize,
                isCode ? "CODE " : "",
                isReadable ? "READ" : "");

            if (!isReadable) continue;  // Can't scan unreadable sections

            // Search for CALL DWORD PTR [WS_SEND] = FF 15 10 36 C5 00
            auto sendSites = FindCallSites(secStart, secSize, KO::IAT::WS_SEND);
            for (DWORD addr : sendSites) {
                DbgLog("    SEND call site at 0x%08X\n", addr);
                CallSite cs;
                cs.address = addr;
                if (PatchCallSite(addr, hookSendAddr, cs.origBytes)) {
                    sendCallSites.push_back(cs);
                    totalSendSites++;
                    // Log patched bytes
                    uint8_t* p = (uint8_t*)addr;
                    DbgLog("      Patched: %02X %02X %02X %02X %02X %02X\n",
                        p[0], p[1], p[2], p[3], p[4], p[5]);
                }
                else {
                    DbgLog("      FAILED to patch!\n");
                }
            }

            // Search for CALL DWORD PTR [WS_RECV] = FF 15 20 36 C5 00
            auto recvSites = FindCallSites(secStart, secSize, KO::IAT::WS_RECV);
            for (DWORD addr : recvSites) {
                DbgLog("    RECV call site at 0x%08X\n", addr);
                CallSite cs;
                cs.address = addr;
                if (PatchCallSite(addr, hookRecvAddr, cs.origBytes)) {
                    recvCallSites.push_back(cs);
                    totalRecvSites++;
                    uint8_t* p = (uint8_t*)addr;
                    DbgLog("      Patched: %02X %02X %02X %02X %02X %02X\n",
                        p[0], p[1], p[2], p[3], p[4], p[5]);
                }
                else {
                    DbgLog("      FAILED to patch!\n");
                }
            }
        }

        DbgLog("\n=== Results ===\n");
        DbgLog("Send call sites found & patched: %d\n", totalSendSites);
        DbgLog("Recv call sites found & patched: %d\n", totalRecvSites);
        DbgLog("System DLL bytes modified: ZERO\n");
        DbgLog("IAT entries modified: ZERO\n");

        if (totalSendSites == 0 && totalRecvSites == 0) {
            DbgLog("\nWARNING: No call sites found!\n");
            DbgLog("The game might use indirect calls (MOV reg, [IAT]; CALL reg)\n");
            DbgLog("or the code sections might be encrypted.\n");

            // Try alternative: scan for MOV reg, [IAT_addr] patterns
            // MOV EAX, [0x00C53610] = A1 10 36 C5 00 (5 bytes)
            // MOV ECX, [0x00C53610] = 8B 0D 10 36 C5 00 (6 bytes)
            // MOV EDX, [0x00C53610] = 8B 15 10 36 C5 00 (6 bytes)
            DbgLog("\nSearching for indirect call patterns (MOV reg, [IAT])...\n");

            for (WORD i = 0; i < numSections; i++) {
                DWORD secStart = (DWORD)hGame + sections[i].VirtualAddress;
                DWORD secSize = sections[i].Misc.VirtualSize;
                if (!(sections[i].Characteristics & IMAGE_SCN_MEM_READ)) continue;

                uint8_t* base = (uint8_t*)secStart;
                for (DWORD j = 0; j + 6 <= secSize; j++) {
                    // Check for A1 [IAT_SEND] (MOV EAX, [0x00C53610])
                    if (base[j] == 0xA1 && *(DWORD*)(base + j + 1) == KO::IAT::WS_SEND) {
                        DbgLog("  MOV EAX, [IAT_send] at 0x%08X\n", secStart + j);
                    }
                    if (base[j] == 0xA1 && *(DWORD*)(base + j + 1) == KO::IAT::WS_RECV) {
                        DbgLog("  MOV EAX, [IAT_recv] at 0x%08X\n", secStart + j);
                    }
                    // Check for 8B xx [IAT] (MOV reg, [0x00C53610])
                    if (base[j] == 0x8B && (base[j+1] & 0xC7) == 0x05) {
                        DWORD target = *(DWORD*)(base + j + 2);
                        if (target == KO::IAT::WS_SEND) {
                            DbgLog("  MOV r32, [IAT_send] at 0x%08X (reg=%02X)\n",
                                secStart + j, base[j+1]);
                        }
                        if (target == KO::IAT::WS_RECV) {
                            DbgLog("  MOV r32, [IAT_recv] at 0x%08X (reg=%02X)\n",
                                secStart + j, base[j+1]);
                        }
                    }
                    // Check for FF 15 with ANY IAT in wsock32 range
                    if (base[j] == 0xFF && base[j+1] == 0x15) {
                        DWORD target = *(DWORD*)(base + j + 2);
                        if (target >= 0x00C53600 && target <= 0x00C53650) {
                            DbgLog("  CALL [0x%08X] at 0x%08X\n", target, secStart + j);
                        }
                    }
                }
            }

            return false;
        }

        // Pre-activate log
        RawLog("=== v7 Hook Runtime Log ===\n");
        RawLogHex("Send call sites: ", (DWORD)totalSendSites);
        RawLogHex("Recv call sites: ", (DWORD)totalRecvSites);
        RawLogHex("realSend: ", (DWORD)realSend);
        RawLogHex("realRecv: ", (DWORD)realRecv);
        RawLog("Call-site hooks ACTIVE\n");

        DbgLog("=== Hook Install Complete (v7 Call-Site) ===\n");
        return true;
    }

    // ---- Remove Hooks ----
    inline void RemoveNetworkHooks() {
        for (auto& cs : sendCallSites)
            RestoreCallSite(cs.address, cs.origBytes);
        for (auto& cs : recvCallSites)
            RestoreCallSite(cs.address, cs.origBytes);
        sendCallSites.clear();
        recvCallSites.clear();
        realSend = nullptr;
        realRecv = nullptr;
        if (logFile) { fclose(logFile); logFile = nullptr; }
        if (hHookLog != INVALID_HANDLE_VALUE) { CloseHandle(hHookLog); hHookLog = INVALID_HANDLE_VALUE; }
    }

    // ---- Get hook stats ----
    inline void GetHookStats(char* buf, int bufSize) {
        sprintf_s(buf, bufSize,
            "Call-sites: send=%zu recv=%zu | Calls: send=%ld recv=%ld",
            sendCallSites.size(), recvCallSites.size(),
            sendHookCount, recvHookCount);
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
