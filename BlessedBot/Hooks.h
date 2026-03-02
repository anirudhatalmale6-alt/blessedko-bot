#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks - Inline detour hooking for send/recv (v2)
// + IAT patching (kept for KODefender bypass use)
//
// v2 fixes:
// - Follows JMP stubs (wsock32 → ws2_32) to find real function
// - Hooks the actual ws2_32 implementation, not the wsock32 stub
// - Relocates relative JMP/CALL instructions in trampoline
// - Non-inline hook functions for stable addresses
// - Dumps function prologue bytes for debugging
// ============================================================

namespace Hooks {

    // Original function pointers (trampolines)
    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    inline tSend oSend = nullptr;
    inline tRecv oRecv = nullptr;
    inline SOCKET gameSocket = INVALID_SOCKET;

    // Trampoline storage
    inline uint8_t* sendTrampoline = nullptr;
    inline uint8_t* recvTrampoline = nullptr;

    // Original bytes for unhooking
    inline uint8_t sendOrigBytes[32] = {};
    inline uint8_t recvOrigBytes[32] = {};
    inline DWORD sendFuncAddr = 0;
    inline DWORD recvFuncAddr = 0;
    inline int sendStolenBytes = 0;
    inline int recvStolenBytes = 0;

    // Debug info string (shown in UI)
    inline char debugInfo[1024] = {};

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
        if (oSend && gameSocket != INVALID_SOCKET) {
            return oSend(gameSocket, (const char*)data, len, 0);
        }
        return -1;
    }

    // Forward declarations for hook implementations (defined at bottom of file)
    __declspec(noinline) int WINAPI hkSendImpl(SOCKET s, const char* buf, int len, int flags);
    __declspec(noinline) int WINAPI hkRecvImpl(SOCKET s, char* buf, int len, int flags);

    // ---- JMP Stub Resolver ----
    // Follow JMP chains to find the real function implementation
    // wsock32.send is often: JMP dword ptr [&ws2_32.send] (FF 25)
    // or: JMP rel32 to ws2_32.send (E9)
    inline DWORD ResolveFunction(DWORD addr) {
        uint8_t* p = (uint8_t*)addr;

        // Follow up to 5 jumps (safety limit)
        for (int i = 0; i < 5; i++) {
            if (p[0] == 0xFF && p[1] == 0x25) {
                // JMP dword ptr [imm32] - indirect jump
                DWORD* pTarget = (DWORD*)(*(DWORD*)(p + 2));
                p = (uint8_t*)*pTarget;
                continue;
            }
            if (p[0] == 0xE9) {
                // JMP rel32 - relative jump
                int32_t offset = *(int32_t*)(p + 1);
                p = p + 5 + offset;
                continue;
            }
            if (p[0] == 0xEB) {
                // JMP rel8 - short jump
                int8_t offset = *(int8_t*)(p + 1);
                p = p + 2 + offset;
                continue;
            }
            // Not a JMP - this is the real function
            break;
        }

        return (DWORD)p;
    }

    // ---- x86 Instruction Length Calculator ----
    // Handles common prologues found in ws2_32 functions
    inline int GetInstructionLength(uint8_t* addr) {
        uint8_t op = *addr;

        // Handle 2-byte opcodes (0x0F prefix)
        if (op == 0x0F) {
            uint8_t op2 = *(addr + 1);
            // Common 0F xx patterns:
            if (op2 >= 0x80 && op2 <= 0x8F) return 6;  // Jcc rel32
            if (op2 == 0x1F) {  // NOP with ModR/M (multi-byte NOP)
                uint8_t modrm = *(addr + 2);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                if (mod == 0 && rm == 0) return 3;       // 0F 1F 00
                if (mod == 1 && rm == 0) return 4;       // 0F 1F 40 xx
                if (mod == 1 && rm == 4) return 5;       // 0F 1F 44 xx xx
                if (mod == 2 && rm == 0) return 7;       // 0F 1F 80 xx xx xx xx
                if (mod == 2 && rm == 4) return 8;       // 0F 1F 84 xx xx xx xx xx
                return 3;  // safe fallback for NOP variants
            }
            if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
                // MOVZX / MOVSX
                uint8_t modrm = *(addr + 2);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                if (mod == 3) return 3;
                if (mod == 0) return (rm == 4) ? 4 : (rm == 5) ? 7 : 3;
                if (mod == 1) return (rm == 4) ? 5 : 4;
                if (mod == 2) return (rm == 4) ? 8 : 7;
                return 3;
            }
            return 2;  // fallback for unknown 0F xx
        }

        // Handle 66 prefix (operand size override)
        if (op == 0x66) {
            // Recurse on the actual opcode, add 1 for prefix
            int innerLen = GetInstructionLength(addr + 1);
            return 1 + innerLen;
        }

        switch (op) {
            case 0x55: return 1; // PUSH EBP
            case 0x56: return 1; // PUSH ESI
            case 0x57: return 1; // PUSH EDI
            case 0x53: return 1; // PUSH EBX
            case 0x50: return 1; // PUSH EAX
            case 0x51: return 1; // PUSH ECX
            case 0x52: return 1; // PUSH EDX
            case 0x54: return 1; // PUSH ESP
            case 0x5D: return 1; // POP EBP
            case 0x5E: return 1; // POP ESI
            case 0x5F: return 1; // POP EDI
            case 0x5B: return 1; // POP EBX
            case 0x58: return 1; // POP EAX
            case 0x59: return 1; // POP ECX
            case 0x5A: return 1; // POP EDX
            case 0x90: return 1; // NOP
            case 0xC3: return 1; // RET
            case 0xCC: return 1; // INT3
            case 0xC9: return 1; // LEAVE
            case 0xF8: return 1; // CLC
            case 0xF9: return 1; // STC
            case 0xFC: return 1; // CLD
            case 0xFD: return 1; // STD

            case 0xC2: return 3; // RET imm16
            case 0xEB: return 2; // JMP rel8
            case 0xE9: return 5; // JMP rel32
            case 0xE8: return 5; // CALL rel32
            case 0xA1: return 5; // MOV EAX, [imm32]
            case 0xA3: return 5; // MOV [imm32], EAX

            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                return 5; // MOV r32, imm32

            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                return 2; // MOV r8, imm8

            case 0x68: return 5; // PUSH imm32
            case 0x6A: return 2; // PUSH imm8

            case 0x04: case 0x0C: case 0x14: case 0x1C:
            case 0x24: case 0x2C: case 0x34: case 0x3C:
            case 0xA8:
                return 2; // ALU AL, imm8 / TEST AL, imm8

            case 0x05: case 0x0D: case 0x15: case 0x1D:
            case 0x25: case 0x2D: case 0x35: case 0x3D:
            case 0xA9:
                return 5; // ALU EAX, imm32 / TEST EAX, imm32

            // Short conditional jumps
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F:
                return 2;

            case 0x80: return 3; // ALU r/m8, imm8
            case 0x83: return 3; // ALU r/m32, imm8
            case 0x81: return 6; // ALU r/m32, imm32
            case 0xC6: return 3; // MOV r/m8, imm8 (simple ModRM)
            case 0xC7: {          // MOV r/m32, imm32
                uint8_t modrm = *(addr + 1);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                int base = 2 + 4; // opcode + modrm + imm32
                if (mod == 3) return base;
                if (mod == 0) {
                    if (rm == 5) return base + 4;  // [disp32]
                    if (rm == 4) return base + 1;  // [SIB]
                    return base;
                }
                if (mod == 1) return base + 1 + (rm == 4 ? 1 : 0); // [reg+disp8] or [SIB+disp8]
                if (mod == 2) return base + 4 + (rm == 4 ? 1 : 0); // [reg+disp32]
                return base;
            }

            // ModR/M based opcodes (2+ bytes)
            case 0x00: case 0x01: case 0x02: case 0x03: // ADD
            case 0x08: case 0x09: case 0x0A: case 0x0B: // OR
            case 0x10: case 0x11: case 0x12: case 0x13: // ADC
            case 0x18: case 0x19: case 0x1A: case 0x1B: // SBB
            case 0x20: case 0x21: case 0x22: case 0x23: // AND
            case 0x28: case 0x29: case 0x2A: case 0x2B: // SUB
            case 0x30: case 0x31: case 0x32: case 0x33: // XOR
            case 0x38: case 0x39: case 0x3A: case 0x3B: // CMP
            case 0x84: case 0x85:                        // TEST
            case 0x86: case 0x87:                        // XCHG
            case 0x88: case 0x89: case 0x8A: case 0x8B: // MOV
            case 0x8D:                                   // LEA
            case 0xD1: case 0xD3:                        // shift/rotate
            case 0xF6: case 0xF7:                        // TEST/NOT/NEG/MUL/DIV
            case 0xFE: case 0xFF:                        // INC/DEC/CALL/JMP/PUSH
            {
                uint8_t modrm = *(addr + 1);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;

                int len = 2; // opcode + modrm
                if (mod == 3) return len;
                if (rm == 4 && mod != 3) len++; // SIB byte
                if (mod == 0 && rm == 5) len += 4; // [disp32]
                else if (mod == 1) len += 1; // disp8
                else if (mod == 2) len += 4; // disp32

                // F6/F7 with reg=0 (TEST) has immediate
                if ((op == 0xF6) && ((modrm >> 3) & 7) == 0) len += 1;
                if ((op == 0xF7) && ((modrm >> 3) & 7) == 0) len += 4;

                return len;
            }

            default:
                return 0; // UNKNOWN - signal error
        }
    }

    // ---- Trampoline Builder (with relocation) ----
    inline uint8_t* CreateTrampoline(uint8_t* targetFunc, int& stolenBytes, char* dbgBuf, int dbgBufSize) {
        stolenBytes = 0;
        int maxAttempt = 32; // safety limit

        // Calculate stolen bytes
        while (stolenBytes < 5 && maxAttempt-- > 0) {
            int len = GetInstructionLength(targetFunc + stolenBytes);
            if (len <= 0) {
                // Unknown instruction - dump bytes for debugging
                sprintf_s(dbgBuf, dbgBufSize,
                    "Unknown instruction at offset %d: %02X %02X %02X %02X",
                    stolenBytes,
                    targetFunc[stolenBytes], targetFunc[stolenBytes + 1],
                    targetFunc[stolenBytes + 2], targetFunc[stolenBytes + 3]);
                return nullptr;
            }
            stolenBytes += len;
        }

        if (stolenBytes < 5) {
            sprintf_s(dbgBuf, dbgBufSize, "Could not find enough bytes to steal (got %d, need 5)", stolenBytes);
            return nullptr;
        }

        // Allocate executable memory for trampoline (generously sized)
        int trampolineSize = stolenBytes + 32; // extra room for relocations
        uint8_t* trampoline = (uint8_t*)VirtualAlloc(nullptr, 64,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline) {
            sprintf_s(dbgBuf, dbgBufSize, "VirtualAlloc failed for trampoline");
            return nullptr;
        }

        // Copy stolen bytes, relocating relative JMP/CALL instructions
        int srcOff = 0;
        int dstOff = 0;
        while (srcOff < stolenBytes) {
            uint8_t op = targetFunc[srcOff];

            if (op == 0xE9) {
                // JMP rel32 - relocate
                int32_t origRel = *(int32_t*)(targetFunc + srcOff + 1);
                DWORD origTarget = (DWORD)(targetFunc + srcOff + 5) + origRel;
                trampoline[dstOff] = 0xE9;
                *(int32_t*)(trampoline + dstOff + 1) =
                    (int32_t)(origTarget - (DWORD)(trampoline + dstOff + 5));
                srcOff += 5;
                dstOff += 5;
            }
            else if (op == 0xE8) {
                // CALL rel32 - relocate
                int32_t origRel = *(int32_t*)(targetFunc + srcOff + 1);
                DWORD origTarget = (DWORD)(targetFunc + srcOff + 5) + origRel;
                trampoline[dstOff] = 0xE8;
                *(int32_t*)(trampoline + dstOff + 1) =
                    (int32_t)(origTarget - (DWORD)(trampoline + dstOff + 5));
                srcOff += 5;
                dstOff += 5;
            }
            else if (op == 0xEB) {
                // JMP rel8 - convert to JMP rel32 for safety
                int8_t origRel = *(int8_t*)(targetFunc + srcOff + 1);
                DWORD origTarget = (DWORD)(targetFunc + srcOff + 2) + origRel;
                trampoline[dstOff] = 0xE9;
                *(int32_t*)(trampoline + dstOff + 1) =
                    (int32_t)(origTarget - (DWORD)(trampoline + dstOff + 5));
                srcOff += 2;
                dstOff += 5;
            }
            else {
                // Regular instruction - copy as-is
                int len = GetInstructionLength(targetFunc + srcOff);
                if (len <= 0) len = 1;
                memcpy(trampoline + dstOff, targetFunc + srcOff, len);
                srcOff += len;
                dstOff += len;
            }
        }

        // Write JMP back to original function after stolen bytes
        DWORD jmpBackAddr = (DWORD)targetFunc + stolenBytes;
        trampoline[dstOff] = 0xE9;
        *(int32_t*)(trampoline + dstOff + 1) =
            (int32_t)(jmpBackAddr - (DWORD)(trampoline + dstOff + 5));

        sprintf_s(dbgBuf, dbgBufSize, "OK: %d bytes stolen, trampoline %d bytes", stolenBytes, dstOff + 5);
        return trampoline;
    }

    // Place JMP detour
    inline bool PlaceDetour(uint8_t* targetFunc, DWORD hookFunc, uint8_t* origBackup, int stolenBytes) {
        DWORD oldProt;
        if (!VirtualProtect(targetFunc, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;

        memcpy(origBackup, targetFunc, stolenBytes);

        targetFunc[0] = 0xE9;
        *(DWORD*)(targetFunc + 1) = hookFunc - (DWORD)(targetFunc + 5);

        for (int i = 5; i < stolenBytes; i++)
            targetFunc[i] = 0x90;

        VirtualProtect(targetFunc, stolenBytes, oldProt, &oldProt);
        return true;
    }

    // Restore original bytes
    inline bool RemoveDetour(uint8_t* targetFunc, uint8_t* origBackup, int stolenBytes) {
        DWORD oldProt;
        if (!VirtualProtect(targetFunc, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;
        memcpy(targetFunc, origBackup, stolenBytes);
        VirtualProtect(targetFunc, stolenBytes, oldProt, &oldProt);
        return true;
    }

    // ---- Hex dump helper ----
    inline void DumpBytes(DWORD addr, int count, char* out, int outSize) {
        int pos = 0;
        for (int i = 0; i < count && pos < outSize - 4; i++) {
            pos += sprintf_s(out + pos, outSize - pos, "%02X ", *(uint8_t*)(addr + i));
        }
    }

    // ---- Install Hooks ----
    inline bool InstallNetworkHooks() {
        int dbgPos = 0;

        // Get wsock32 send/recv addresses
        HMODULE hWsock = GetModuleHandleA("wsock32.dll");
        if (!hWsock) hWsock = LoadLibraryA("wsock32.dll");
        if (!hWsock) {
            sprintf_s(debugInfo, "wsock32.dll not found");
            return false;
        }

        DWORD rawSend = (DWORD)GetProcAddress(hWsock, "send");
        DWORD rawRecv = (DWORD)GetProcAddress(hWsock, "recv");

        if (!rawSend || !rawRecv) {
            sprintf_s(debugInfo, "GetProcAddress failed");
            return false;
        }

        // Dump raw function bytes
        char sendDump[128], recvDump[128];
        DumpBytes(rawSend, 16, sendDump, sizeof(sendDump));
        DumpBytes(rawRecv, 16, recvDump, sizeof(recvDump));

        dbgPos += sprintf_s(debugInfo + dbgPos, sizeof(debugInfo) - dbgPos,
            "wsock32.send raw: 0x%08X [%s]\n", rawSend, sendDump);
        dbgPos += sprintf_s(debugInfo + dbgPos, sizeof(debugInfo) - dbgPos,
            "wsock32.recv raw: 0x%08X [%s]\n", rawRecv, recvDump);

        // Resolve JMP stubs to find real functions (typically in ws2_32.dll)
        sendFuncAddr = ResolveFunction(rawSend);
        recvFuncAddr = ResolveFunction(rawRecv);

        DumpBytes(sendFuncAddr, 16, sendDump, sizeof(sendDump));
        DumpBytes(recvFuncAddr, 16, recvDump, sizeof(recvDump));

        dbgPos += sprintf_s(debugInfo + dbgPos, sizeof(debugInfo) - dbgPos,
            "Resolved send: 0x%08X [%s]\n", sendFuncAddr, sendDump);
        dbgPos += sprintf_s(debugInfo + dbgPos, sizeof(debugInfo) - dbgPos,
            "Resolved recv: 0x%08X [%s]\n", recvFuncAddr, recvDump);

        // Check if the resolved address has a hot-patch prologue (MOV EDI, EDI = 8B FF)
        // If so, we can use the 5 NOP bytes before the function for a cleaner hook
        uint8_t* pSend = (uint8_t*)sendFuncAddr;
        uint8_t* pRecv = (uint8_t*)recvFuncAddr;

        bool sendHotPatch = (pSend[0] == 0x8B && pSend[1] == 0xFF);
        bool recvHotPatch = (pRecv[0] == 0x8B && pRecv[1] == 0xFF);

        dbgPos += sprintf_s(debugInfo + dbgPos, sizeof(debugInfo) - dbgPos,
            "Hot-patch: send=%s recv=%s\n",
            sendHotPatch ? "YES" : "NO",
            recvHotPatch ? "YES" : "NO");

        // Create trampolines
        char sendTrResult[256], recvTrResult[256];
        sendTrampoline = CreateTrampoline(pSend, sendStolenBytes, sendTrResult, sizeof(sendTrResult));
        recvTrampoline = CreateTrampoline(pRecv, recvStolenBytes, recvTrResult, sizeof(recvTrResult));

        dbgPos += sprintf_s(debugInfo + dbgPos, sizeof(debugInfo) - dbgPos,
            "Send trampoline: %s\n", sendTrResult);
        dbgPos += sprintf_s(debugInfo + dbgPos, sizeof(debugInfo) - dbgPos,
            "Recv trampoline: %s\n", recvTrResult);

        if (!sendTrampoline || !recvTrampoline) {
            return false;
        }

        // Set original function pointers to trampolines
        oSend = (tSend)sendTrampoline;
        oRecv = (tRecv)recvTrampoline;

        // Place detours
        bool sendOk = PlaceDetour(pSend, (DWORD)&hkSendImpl, sendOrigBytes, sendStolenBytes);
        bool recvOk = PlaceDetour(pRecv, (DWORD)&hkRecvImpl, recvOrigBytes, recvStolenBytes);

        dbgPos += sprintf_s(debugInfo + dbgPos, sizeof(debugInfo) - dbgPos,
            "Detour placed: send=%s recv=%s\n",
            sendOk ? "OK" : "FAIL",
            recvOk ? "OK" : "FAIL");

        return sendOk && recvOk;
    }

    // ---- Remove Hooks ----
    inline void RemoveNetworkHooks() {
        if (sendFuncAddr && sendStolenBytes > 0)
            RemoveDetour((uint8_t*)sendFuncAddr, sendOrigBytes, sendStolenBytes);
        if (recvFuncAddr && recvStolenBytes > 0)
            RemoveDetour((uint8_t*)recvFuncAddr, recvOrigBytes, recvStolenBytes);
        if (sendTrampoline) { VirtualFree(sendTrampoline, 0, MEM_RELEASE); sendTrampoline = nullptr; }
        if (recvTrampoline) { VirtualFree(recvTrampoline, 0, MEM_RELEASE); recvTrampoline = nullptr; }
        oSend = nullptr;
        oRecv = nullptr;
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

    // ---- Hook implementations (NOT inline - need stable addresses) ----
    // Using __declspec(noinline) to guarantee the compiler gives us a real function address

    __declspec(noinline) int WINAPI hkSendImpl(SOCKET s, const char* buf, int len, int flags) {
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

        return oSend(s, buf, len, flags);
    }

    __declspec(noinline) int WINAPI hkRecvImpl(SOCKET s, char* buf, int len, int flags) {
        int result = oRecv(s, buf, len, flags);

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

} // namespace Hooks
