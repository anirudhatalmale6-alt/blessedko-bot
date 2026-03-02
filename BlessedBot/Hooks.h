#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include <cstdio>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks v3 - Simplified approach
//
// On modern Windows, wsock32.send/recv are JMP stubs to ws2_32.dll:
//   wsock32.send: FF 25 xx xx xx xx  (JMP dword ptr [ws2_32.send])
//
// Strategy:
// 1. Resolve the real ws2_32.send/recv addresses
// 2. Replace the wsock32 JMP stub with JMP to our hook (5-6 bytes)
// 3. Our hook calls ws2_32.send/recv DIRECTLY via saved pointer
// 4. NO TRAMPOLINE NEEDED - eliminates all relocation bugs
//
// KODefender checks the game's IAT (which still points to wsock32.send)
// so it sees no change. We only modify wsock32's code section.
// ============================================================

namespace Hooks {

    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    // Direct pointers to the REAL ws2_32 functions (not stubs)
    inline tSend pRealSend = nullptr;
    inline tRecv pRealRecv = nullptr;

    inline SOCKET gameSocket = INVALID_SOCKET;

    // Hook target addresses (wsock32 stub locations)
    inline DWORD wsockSendAddr = 0;
    inline DWORD wsockRecvAddr = 0;

    // Original bytes for unhooking
    inline uint8_t sendOrigBytes[8] = {};
    inline uint8_t recvOrigBytes[8] = {};
    inline int sendPatchSize = 0;
    inline int recvPatchSize = 0;

    // Debug log file
    inline FILE* logFile = nullptr;

    inline void LogToFile(const char* fmt, ...) {
        if (!logFile) {
            fopen_s(&logFile, "BlessedBot_debug.log", "a");
        }
        if (logFile) {
            va_list args;
            va_start(args, fmt);
            vfprintf(logFile, fmt, args);
            va_end(args);
            fflush(logFile);
        }
    }

    // Debug info for UI
    inline char debugInfo[2048] = {};
    inline int debugPos = 0;

    inline void DbgLog(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        int written = vsnprintf(debugInfo + debugPos, sizeof(debugInfo) - debugPos, fmt, args);
        va_end(args);
        if (written > 0) debugPos += written;

        // Also write to file for crash safety
        va_start(args, fmt);
        LogToFile("[HOOK] ");
        if (logFile) {
            vfprintf(logFile, fmt, args);
            fflush(logFile);
        }
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
        if (pRealSend && gameSocket != INVALID_SOCKET) {
            return pRealSend(gameSocket, (const char*)data, len, 0);
        }
        return -1;
    }

    // ---- Hook implementations ----
    // These call ws2_32 functions DIRECTLY - no trampoline

    __declspec(noinline) static int WINAPI hkSendImpl(SOCKET s, const char* buf, int len, int flags) {
        if (gameSocket == INVALID_SOCKET)
            gameSocket = s;

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

        // Call the REAL ws2_32.send directly
        return pRealSend(s, buf, len, flags);
    }

    __declspec(noinline) static int WINAPI hkRecvImpl(SOCKET s, char* buf, int len, int flags) {
        // Call the REAL ws2_32.recv directly
        int result = pRealRecv(s, buf, len, flags);

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

    // ---- Hex dump helper ----
    inline void HexDump(DWORD addr, int count, char* out, int outSize) {
        int pos = 0;
        for (int i = 0; i < count && pos < outSize - 4; i++) {
            pos += sprintf_s(out + pos, outSize - pos, "%02X ", *(uint8_t*)(addr + i));
        }
    }

    // ---- Resolve JMP stub to find real function ----
    inline DWORD ResolveFunction(DWORD addr, const char* name) {
        uint8_t* p = (uint8_t*)addr;

        for (int i = 0; i < 5; i++) {
            if (p[0] == 0xFF && p[1] == 0x25) {
                // JMP dword ptr [imm32] - indirect absolute jump
                DWORD ptrAddr = *(DWORD*)(p + 2);
                DWORD target = *(DWORD*)ptrAddr;
                DbgLog("  %s: FF 25 stub -> ptr at 0x%08X -> target 0x%08X\n", name, ptrAddr, target);
                p = (uint8_t*)target;
                continue;
            }
            if (p[0] == 0xE9) {
                // JMP rel32
                int32_t offset = *(int32_t*)(p + 1);
                DWORD target = (DWORD)p + 5 + offset;
                DbgLog("  %s: E9 rel32 -> target 0x%08X\n", name, target);
                p = (uint8_t*)target;
                continue;
            }
            if (p[0] == 0xEB) {
                // JMP rel8
                int8_t offset = *(int8_t*)(p + 1);
                DWORD target = (DWORD)p + 2 + offset;
                DbgLog("  %s: EB rel8 -> target 0x%08X\n", name, target);
                p = (uint8_t*)target;
                continue;
            }
            break;
        }

        return (DWORD)p;
    }

    // ---- Write a JMP at target address ----
    inline bool WriteJmp(DWORD targetAddr, DWORD hookAddr, uint8_t* backup, int patchSize) {
        DWORD oldProt;
        if (!VirtualProtect((void*)targetAddr, patchSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
            DbgLog("  VirtualProtect failed: error %d\n", GetLastError());
            return false;
        }

        // Backup original bytes
        memcpy(backup, (void*)targetAddr, patchSize);

        // Write JMP rel32
        *(uint8_t*)targetAddr = 0xE9;
        *(int32_t*)(targetAddr + 1) = (int32_t)(hookAddr - (targetAddr + 5));

        // NOP remaining bytes
        for (int i = 5; i < patchSize; i++)
            *(uint8_t*)(targetAddr + i) = 0x90;

        VirtualProtect((void*)targetAddr, patchSize, oldProt, &oldProt);
        return true;
    }

    // ---- Restore original bytes ----
    inline bool RestoreBytes(DWORD targetAddr, uint8_t* backup, int patchSize) {
        DWORD oldProt;
        if (!VirtualProtect((void*)targetAddr, patchSize, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;
        memcpy((void*)targetAddr, backup, patchSize);
        VirtualProtect((void*)targetAddr, patchSize, oldProt, &oldProt);
        return true;
    }

    // ---- Install Hooks ----
    inline bool InstallNetworkHooks() {
        debugPos = 0;
        memset(debugInfo, 0, sizeof(debugInfo));

        DbgLog("=== Hook Install v3 ===\n");

        // Step 1: Get wsock32 module
        HMODULE hWsock = GetModuleHandleA("wsock32.dll");
        if (!hWsock) hWsock = LoadLibraryA("wsock32.dll");
        if (!hWsock) {
            DbgLog("FAIL: wsock32.dll not found\n");
            return false;
        }
        DbgLog("wsock32.dll at: 0x%08X\n", (DWORD)hWsock);

        // Also get ws2_32 module
        HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
        if (!hWs2) hWs2 = LoadLibraryA("ws2_32.dll");
        DbgLog("ws2_32.dll at: 0x%08X\n", (DWORD)hWs2);

        // Step 2: Get wsock32 export addresses
        wsockSendAddr = (DWORD)GetProcAddress(hWsock, "send");
        wsockRecvAddr = (DWORD)GetProcAddress(hWsock, "recv");

        if (!wsockSendAddr || !wsockRecvAddr) {
            DbgLog("FAIL: GetProcAddress failed\n");
            return false;
        }

        // Dump raw bytes
        char hexBuf[128];
        HexDump(wsockSendAddr, 16, hexBuf, sizeof(hexBuf));
        DbgLog("wsock32.send (0x%08X): %s\n", wsockSendAddr, hexBuf);
        HexDump(wsockRecvAddr, 16, hexBuf, sizeof(hexBuf));
        DbgLog("wsock32.recv (0x%08X): %s\n", wsockRecvAddr, hexBuf);

        // Step 3: Resolve to real ws2_32 functions
        DbgLog("Resolving JMP stubs...\n");
        DWORD realSend = ResolveFunction(wsockSendAddr, "send");
        DWORD realRecv = ResolveFunction(wsockRecvAddr, "recv");

        HexDump(realSend, 16, hexBuf, sizeof(hexBuf));
        DbgLog("Real send (0x%08X): %s\n", realSend, hexBuf);
        HexDump(realRecv, 16, hexBuf, sizeof(hexBuf));
        DbgLog("Real recv (0x%08X): %s\n", realRecv, hexBuf);

        // Also try getting ws2_32 exports directly for comparison
        if (hWs2) {
            DWORD ws2Send = (DWORD)GetProcAddress(hWs2, "send");
            DWORD ws2Recv = (DWORD)GetProcAddress(hWs2, "recv");
            DbgLog("ws2_32.send direct: 0x%08X (match: %s)\n", ws2Send,
                ws2Send == realSend ? "YES" : "NO");
            DbgLog("ws2_32.recv direct: 0x%08X (match: %s)\n", ws2Recv,
                ws2Recv == realRecv ? "YES" : "NO");
        }

        // Step 4: Save real function pointers
        pRealSend = (tSend)realSend;
        pRealRecv = (tRecv)realRecv;

        // Step 5: Determine patch size for the wsock32 stubs
        // FF 25 stubs are 6 bytes, E9 stubs are 5 bytes
        uint8_t* pSend = (uint8_t*)wsockSendAddr;
        uint8_t* pRecv = (uint8_t*)wsockRecvAddr;

        if (pSend[0] == 0xFF && pSend[1] == 0x25) {
            sendPatchSize = 6;  // FF 25 xx xx xx xx
            DbgLog("send stub: FF 25 indirect JMP (6 bytes)\n");
        }
        else if (pSend[0] == 0xE9) {
            sendPatchSize = 5;  // E9 xx xx xx xx
            DbgLog("send stub: E9 relative JMP (5 bytes)\n");
        }
        else {
            // Not a stub - it's the real function. Hook it directly.
            // Need at least 5 bytes. Assume standard prologue.
            sendPatchSize = 5;
            DbgLog("send: NOT a stub, hooking directly (5 bytes)\n");
            // In this case, we can't just call pRealSend - we need a trampoline
            // For now, try to use ws2_32.send directly
            if (hWs2) {
                DWORD ws2Send = (DWORD)GetProcAddress(hWs2, "send");
                if (ws2Send && ws2Send != wsockSendAddr) {
                    pRealSend = (tSend)ws2Send;
                    DbgLog("  Using ws2_32.send (0x%08X) as original\n", ws2Send);
                }
                else {
                    DbgLog("  WARNING: Cannot find alternate send - may crash!\n");
                }
            }
        }

        if (pRecv[0] == 0xFF && pRecv[1] == 0x25) {
            recvPatchSize = 6;
            DbgLog("recv stub: FF 25 indirect JMP (6 bytes)\n");
        }
        else if (pRecv[0] == 0xE9) {
            recvPatchSize = 5;
            DbgLog("recv stub: E9 relative JMP (5 bytes)\n");
        }
        else {
            recvPatchSize = 5;
            DbgLog("recv: NOT a stub, hooking directly (5 bytes)\n");
            if (hWs2) {
                DWORD ws2Recv = (DWORD)GetProcAddress(hWs2, "recv");
                if (ws2Recv && ws2Recv != wsockRecvAddr) {
                    pRealRecv = (tRecv)ws2Recv;
                    DbgLog("  Using ws2_32.recv (0x%08X) as original\n", ws2Recv);
                }
            }
        }

        // Step 6: Get our hook function addresses
        DWORD hookSendAddr = (DWORD)&hkSendImpl;
        DWORD hookRecvAddr = (DWORD)&hkRecvImpl;
        DbgLog("hkSendImpl at: 0x%08X\n", hookSendAddr);
        DbgLog("hkRecvImpl at: 0x%08X\n", hookRecvAddr);

        // Step 7: Write the JMP hooks
        DbgLog("Writing hooks...\n");

        bool sendOk = WriteJmp(wsockSendAddr, hookSendAddr, sendOrigBytes, sendPatchSize);
        DbgLog("send hook: %s\n", sendOk ? "OK" : "FAIL");

        bool recvOk = WriteJmp(wsockRecvAddr, hookRecvAddr, recvOrigBytes, recvPatchSize);
        DbgLog("recv hook: %s\n", recvOk ? "OK" : "FAIL");

        // Verify the patch
        if (sendOk) {
            HexDump(wsockSendAddr, 8, hexBuf, sizeof(hexBuf));
            DbgLog("send after patch: %s\n", hexBuf);
        }
        if (recvOk) {
            HexDump(wsockRecvAddr, 8, hexBuf, sizeof(hexBuf));
            DbgLog("recv after patch: %s\n", hexBuf);
        }

        DbgLog("=== Hook Install Complete ===\n");

        return sendOk && recvOk;
    }

    // ---- Remove Hooks ----
    inline void RemoveNetworkHooks() {
        if (wsockSendAddr && sendPatchSize > 0)
            RestoreBytes(wsockSendAddr, sendOrigBytes, sendPatchSize);
        if (wsockRecvAddr && recvPatchSize > 0)
            RestoreBytes(wsockRecvAddr, recvOrigBytes, recvPatchSize);
        pRealSend = nullptr;
        pRealRecv = nullptr;
        if (logFile) { fclose(logFile); logFile = nullptr; }
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
