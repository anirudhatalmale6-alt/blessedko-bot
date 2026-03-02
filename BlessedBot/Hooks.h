#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include <cstdio>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks v5 - Hot-Patch Hooking + Crash Diagnostics
//
// v4 hot-patch math verified correct, but still crashes on first
// packet. v5 adds:
// 1. FlushInstructionCache after all code modifications
// 2. SEH wrapper around hook functions (catches crashes)
// 3. Win32-level logging inside hooks (no CRT, crash-safe)
// 4. Volatile function pointers to prevent optimizer issues
// 5. Logs oSend/oRecv values from inside hook to verify routing
// ============================================================

namespace Hooks {

    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    // Original function trampolines - VOLATILE to prevent optimizer caching
    inline volatile tSend oSend = nullptr;
    inline volatile tRecv oRecv = nullptr;

    inline volatile SOCKET gameSocket = INVALID_SOCKET;

    // Hooked function addresses
    inline DWORD sendFuncAddr = 0;
    inline DWORD recvFuncAddr = 0;

    // Original bytes for unhooking
    inline uint8_t sendOrigPad[5] = {};
    inline uint8_t sendOrigHead[2] = {};
    inline uint8_t recvOrigPad[5] = {};
    inline uint8_t recvOrigHead[2] = {};

    // Trampolines (allocated executable memory)
    inline uint8_t* sendTrampoline = nullptr;
    inline uint8_t* recvTrampoline = nullptr;

    // Hook call counters
    inline volatile LONG sendHookCount = 0;
    inline volatile LONG recvHookCount = 0;
    inline volatile LONG sendCrashCount = 0;
    inline volatile LONG recvCrashCount = 0;

    // ==== Win32-only crash-safe logging (no CRT) ====
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
        // Manual hex formatting (no CRT)
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

    // ==== Install-time debug logging (CRT-based, for debugInfo UI) ====
    inline FILE* logFile = nullptr;
    inline char debugInfo[4096] = {};
    inline int debugPos = 0;

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
        volatile tSend fn = oSend;
        volatile SOCKET sock = gameSocket;
        if (fn && sock != INVALID_SOCKET)
            return fn(sock, (const char*)data, len, 0);
        return -1;
    }

    // ==== Hook implementations (C++ internals) ====
    __declspec(noinline) static int WINAPI hkSendInner(SOCKET s, const char* buf, int len, int flags) {
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

        // Read volatile pointer and call trampoline
        volatile tSend fn = oSend;
        return fn(s, buf, len, flags);
    }

    __declspec(noinline) static int WINAPI hkRecvInner(SOCKET s, char* buf, int len, int flags) {
        // Read volatile pointer and call trampoline
        volatile tRecv fn = oRecv;
        int result = fn(s, buf, len, flags);

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

    // ==== SEH wrapper hooks (NO C++ objects - safe for __try/__except) ====
    // These are the actual hook entry points. They log, then call the C++ inner function.
    // If anything crashes, SEH catches it and calls original directly via trampoline.

    __declspec(noinline) static int WINAPI hkSendImpl(SOCKET s, const char* buf, int len, int flags) {
        LONG count = InterlockedIncrement(&sendHookCount);

        // Log on first call only (to avoid flooding)
        if (count == 1) {
            RawLog("=== hkSendImpl ENTERED (first call) ===\n");
            RawLogHex("  oSend = ", (DWORD)oSend);
            RawLogHex("  sendTrampoline = ", (DWORD)sendTrampoline);
            RawLogHex("  sendFuncAddr = ", sendFuncAddr);
            RawLogHex("  socket = ", (DWORD)s);
            RawLogHex("  buf = ", (DWORD)buf);
            RawLogHex("  len = ", (DWORD)len);
        }

        __try {
            return hkSendInner(s, buf, len, flags);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement(&sendCrashCount);
            if (sendCrashCount <= 3) {
                RawLog("!!! hkSendImpl CRASHED - SEH caught !!!\n");
                RawLogHex("  Exception at call #", (DWORD)count);
                RawLogHex("  oSend = ", (DWORD)oSend);
            }
            // Fall back to calling trampoline directly
            volatile tSend fn = oSend;
            if (fn) return fn(s, buf, len, flags);
            return -1;
        }
    }

    __declspec(noinline) static int WINAPI hkRecvImpl(SOCKET s, char* buf, int len, int flags) {
        LONG count = InterlockedIncrement(&recvHookCount);

        if (count == 1) {
            RawLog("=== hkRecvImpl ENTERED (first call) ===\n");
            RawLogHex("  oRecv = ", (DWORD)oRecv);
            RawLogHex("  recvTrampoline = ", (DWORD)recvTrampoline);
            RawLogHex("  recvFuncAddr = ", recvFuncAddr);
            RawLogHex("  socket = ", (DWORD)s);
        }

        __try {
            return hkRecvInner(s, buf, len, flags);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement(&recvCrashCount);
            if (recvCrashCount <= 3) {
                RawLog("!!! hkRecvImpl CRASHED - SEH caught !!!\n");
                RawLogHex("  Exception at call #", (DWORD)count);
                RawLogHex("  oRecv = ", (DWORD)oRecv);
            }
            volatile tRecv fn = oRecv;
            if (fn) return fn(s, buf, len, flags);
            return -1;
        }
    }

    // ---- Hex dump helper ----
    inline void HexDump(DWORD addr, int count, char* out, int outSize) {
        int pos = 0;
        for (int i = 0; i < count && pos < outSize - 4; i++)
            pos += sprintf_s(out + pos, outSize - pos, "%02X ", *(uint8_t*)(addr + i));
    }

    // ---- Create hot-patch trampoline ----
    inline uint8_t* CreateHotPatchTrampoline(DWORD funcAddr) {
        uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 16,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tramp) return nullptr;

        // MOV EDI, EDI (the original 2-byte NOP we're replacing)
        tramp[0] = 0x8B;
        tramp[1] = 0xFF;

        // JMP to funcAddr + 2 (skip past our EB F9 short jmp)
        tramp[2] = 0xE9;
        DWORD jmpTarget = funcAddr + 2;
        *(int32_t*)(tramp + 3) = (int32_t)(jmpTarget - (DWORD)(tramp + 7));

        // Flush instruction cache for trampoline
        FlushInstructionCache(GetCurrentProcess(), tramp, 16);

        return tramp;
    }

    // ---- Apply hot-patch hook ----
    inline bool ApplyHotPatch(DWORD funcAddr, DWORD hookAddr,
        uint8_t* backupPad, uint8_t* backupHead, const char* name) {

        uint8_t* pFunc = (uint8_t*)funcAddr;

        // Verify hot-patch prologue
        if (pFunc[0] != 0x8B || pFunc[1] != 0xFF) {
            DbgLog("%s: NOT hot-patchable (bytes: %02X %02X, expected 8B FF)\n",
                name, pFunc[0], pFunc[1]);
            return false;
        }

        // Check the 5 bytes before the function
        uint8_t* pPad = pFunc - 5;
        bool padOk = true;
        for (int i = 0; i < 5; i++) {
            if (pPad[i] != 0xCC && pPad[i] != 0x90 && pPad[i] != 0x00) {
                padOk = false;
                break;
            }
        }

        char hexBuf[64];
        HexDump((DWORD)pPad, 5, hexBuf, sizeof(hexBuf));
        DbgLog("%s: padding bytes [-5]: %s (%s)\n", name, hexBuf, padOk ? "OK" : "NOT standard padding");

        if (!padOk) {
            DbgLog("%s: WARNING - padding not standard, but proceeding anyway\n", name);
        }

        // Backup original bytes
        memcpy(backupPad, pPad, 5);
        memcpy(backupHead, pFunc, 2);

        // Unprotect the 7-byte region: [funcAddr-5 ... funcAddr+1]
        DWORD oldProt;
        if (!VirtualProtect(pPad, 7, PAGE_EXECUTE_READWRITE, &oldProt)) {
            DbgLog("%s: VirtualProtect failed: %d\n", name, GetLastError());
            return false;
        }

        // Step 1: Write JMP rel32 in the 5-byte padding BEFORE function
        pPad[0] = 0xE9;
        *(int32_t*)(pPad + 1) = (int32_t)(hookAddr - (DWORD)(pPad + 5));

        // Step 2: Replace MOV EDI,EDI with JMP SHORT -7
        // (JMP SHORT offset is relative to NEXT instruction = funcAddr+2)
        // Target: funcAddr+2 + (-7) = funcAddr-5 = pPad
        pFunc[0] = 0xEB;
        pFunc[1] = 0xF9;  // -7 signed

        // Restore original protection
        VirtualProtect(pPad, 7, oldProt, &oldProt);

        // CRITICAL: Flush instruction cache so other CPUs/threads see new code
        FlushInstructionCache(GetCurrentProcess(), pPad, 7);

        // Verify
        HexDump((DWORD)pPad, 7, hexBuf, sizeof(hexBuf));
        DbgLog("%s: patched [-5..+2]: %s\n", name, hexBuf);

        // Also verify trampoline target
        DbgLog("%s: hook target = 0x%08X, trampoline returns to = 0x%08X\n",
            name, hookAddr, funcAddr + 2);

        return true;
    }

    // ---- Restore hot-patch ----
    inline bool RestoreHotPatch(DWORD funcAddr, uint8_t* backupPad, uint8_t* backupHead) {
        uint8_t* pFunc = (uint8_t*)funcAddr;
        uint8_t* pPad = pFunc - 5;

        DWORD oldProt;
        if (!VirtualProtect(pPad, 7, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;

        memcpy(pPad, backupPad, 5);
        memcpy(pFunc, backupHead, 2);

        VirtualProtect(pPad, 7, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), pPad, 7);
        return true;
    }

    // ---- Install Hooks ----
    inline bool InstallNetworkHooks() {
        debugPos = 0;
        memset(debugInfo, 0, sizeof(debugInfo));

        DbgLog("=== Hook Install v5 (Hot-Patch + SEH + Diagnostics) ===\n");

        // Get module handles
        HMODULE hWsock = GetModuleHandleA("wsock32.dll");
        if (!hWsock) hWsock = LoadLibraryA("wsock32.dll");
        HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
        if (!hWs2) hWs2 = LoadLibraryA("ws2_32.dll");

        if (!hWsock) { DbgLog("FAIL: wsock32.dll not found\n"); return false; }

        DbgLog("wsock32.dll at: 0x%08X\n", (DWORD)hWsock);
        DbgLog("ws2_32.dll at: 0x%08X\n", (DWORD)hWs2);

        // Get export addresses
        DWORD wsockSend = (DWORD)GetProcAddress(hWsock, "send");
        DWORD wsockRecv = (DWORD)GetProcAddress(hWsock, "recv");
        DWORD ws2Send = hWs2 ? (DWORD)GetProcAddress(hWs2, "send") : 0;
        DWORD ws2Recv = hWs2 ? (DWORD)GetProcAddress(hWs2, "recv") : 0;

        char hexBuf[128];

        HexDump(wsockSend, 16, hexBuf, sizeof(hexBuf));
        DbgLog("wsock32.send (0x%08X): %s\n", wsockSend, hexBuf);
        HexDump(wsockRecv, 16, hexBuf, sizeof(hexBuf));
        DbgLog("wsock32.recv (0x%08X): %s\n", wsockRecv, hexBuf);

        if (ws2Send) {
            HexDump(ws2Send, 16, hexBuf, sizeof(hexBuf));
            DbgLog("ws2_32.send (0x%08X): %s\n", ws2Send, hexBuf);
        }
        if (ws2Recv) {
            HexDump(ws2Recv, 16, hexBuf, sizeof(hexBuf));
            DbgLog("ws2_32.recv (0x%08X): %s\n", ws2Recv, hexBuf);
        }

        DbgLog("wsock32.send == ws2_32.send? %s\n", wsockSend == ws2Send ? "YES (forwarded)" : "NO");
        DbgLog("wsock32.recv == ws2_32.recv? %s\n", wsockRecv == ws2Recv ? "YES (forwarded)" : "NO");

        sendFuncAddr = wsockSend;
        recvFuncAddr = wsockRecv;

        DbgLog("\nHooking send at: 0x%08X\n", sendFuncAddr);
        DbgLog("Hooking recv at: 0x%08X\n", recvFuncAddr);

        // Create trampolines
        sendTrampoline = CreateHotPatchTrampoline(sendFuncAddr);
        recvTrampoline = CreateHotPatchTrampoline(recvFuncAddr);

        if (!sendTrampoline || !recvTrampoline) {
            DbgLog("FAIL: Could not allocate trampolines\n");
            return false;
        }

        // Set originals to trampolines BEFORE patching
        oSend = (tSend)sendTrampoline;
        oRecv = (tRecv)recvTrampoline;

        DbgLog("send trampoline at: 0x%08X\n", (DWORD)sendTrampoline);
        DbgLog("recv trampoline at: 0x%08X\n", (DWORD)recvTrampoline);
        DbgLog("oSend = 0x%08X (should match send trampoline)\n", (DWORD)oSend);
        DbgLog("oRecv = 0x%08X (should match recv trampoline)\n", (DWORD)oRecv);

        // Verify trampoline bytes
        HexDump((DWORD)sendTrampoline, 7, hexBuf, sizeof(hexBuf));
        DbgLog("send trampoline bytes: %s\n", hexBuf);
        HexDump((DWORD)recvTrampoline, 7, hexBuf, sizeof(hexBuf));
        DbgLog("recv trampoline bytes: %s\n", hexBuf);

        // Get SEH wrapper hook addresses (NOT the inner functions)
        DWORD hookSendAddr = (DWORD)&hkSendImpl;
        DWORD hookRecvAddr = (DWORD)&hkRecvImpl;
        DbgLog("hkSendImpl (SEH wrapper) at: 0x%08X\n", hookSendAddr);
        DbgLog("hkRecvImpl (SEH wrapper) at: 0x%08X\n", hookRecvAddr);
        DbgLog("hkSendInner at: 0x%08X\n", (DWORD)&hkSendInner);
        DbgLog("hkRecvInner at: 0x%08X\n", (DWORD)&hkRecvInner);

        // Test: call trampoline BEFORE patching (should call original function normally)
        DbgLog("\nPre-patch trampoline test...\n");
        __try {
            // send trampoline: MOV EDI,EDI + JMP to sendFunc+2
            // This should execute the original send function (which currently has 8B FF at start)
            // But we can't actually call send without a socket, so just verify the trampoline is executable
            uint8_t firstByte = sendTrampoline[0];
            uint8_t secondByte = sendTrampoline[1];
            DbgLog("send trampoline readable: %02X %02X (should be 8B FF)\n", firstByte, secondByte);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgLog("WARNING: trampoline memory not readable!\n");
        }

        // Apply hot-patches
        DbgLog("\nApplying hot-patches...\n");

        bool sendOk = ApplyHotPatch(sendFuncAddr, hookSendAddr, sendOrigPad, sendOrigHead, "send");
        bool recvOk = ApplyHotPatch(recvFuncAddr, hookRecvAddr, recvOrigPad, recvOrigHead, "recv");

        // Final verification: re-read oSend/oRecv to confirm they weren't clobbered
        DbgLog("\nPost-patch verification:\n");
        DbgLog("oSend = 0x%08X (should be 0x%08X)\n", (DWORD)oSend, (DWORD)sendTrampoline);
        DbgLog("oRecv = 0x%08X (should be 0x%08X)\n", (DWORD)oRecv, (DWORD)recvTrampoline);

        // Verify patched function bytes
        HexDump(sendFuncAddr, 8, hexBuf, sizeof(hexBuf));
        DbgLog("send func now: %s (should start with EB F9)\n", hexBuf);
        HexDump(recvFuncAddr, 8, hexBuf, sizeof(hexBuf));
        DbgLog("recv func now: %s (should start with EB F9)\n", hexBuf);

        // Verify bytes at funcAddr+2 (where trampoline jumps to)
        HexDump(sendFuncAddr + 2, 8, hexBuf, sizeof(hexBuf));
        DbgLog("send at +2: %s (should be 55 8B EC = PUSH EBP; MOV EBP,ESP)\n", hexBuf);
        HexDump(recvFuncAddr + 2, 8, hexBuf, sizeof(hexBuf));
        DbgLog("recv at +2: %s (should be 55 8B EC = PUSH EBP; MOV EBP,ESP)\n", hexBuf);

        DbgLog("\nResult: send=%s recv=%s\n", sendOk ? "OK" : "FAIL", recvOk ? "OK" : "FAIL");
        DbgLog("=== Hook Install Complete ===\n");
        DbgLog("=== Check BlessedBot_hook.log for runtime hook diagnostics ===\n");

        return sendOk && recvOk;
    }

    // ---- Remove Hooks ----
    inline void RemoveNetworkHooks() {
        if (sendFuncAddr)
            RestoreHotPatch(sendFuncAddr, sendOrigPad, sendOrigHead);
        if (recvFuncAddr)
            RestoreHotPatch(recvFuncAddr, recvOrigPad, recvOrigHead);
        if (sendTrampoline) { VirtualFree(sendTrampoline, 0, MEM_RELEASE); sendTrampoline = nullptr; }
        if (recvTrampoline) { VirtualFree(recvTrampoline, 0, MEM_RELEASE); recvTrampoline = nullptr; }
        oSend = nullptr;
        oRecv = nullptr;
        if (logFile) { fclose(logFile); logFile = nullptr; }
        if (hHookLog != INVALID_HANDLE_VALUE) { CloseHandle(hHookLog); hHookLog = INVALID_HANDLE_VALUE; }
    }

    // ---- Get hook stats for UI ----
    inline void GetHookStats(char* buf, int bufSize) {
        sprintf_s(buf, bufSize,
            "Send hooks: %ld (crashes: %ld) | Recv hooks: %ld (crashes: %ld)",
            sendHookCount, sendCrashCount, recvHookCount, recvCrashCount);
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
