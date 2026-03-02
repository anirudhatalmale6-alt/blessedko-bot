#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <functional>
#include "../Common/KOStructs.h"

// ============================================================
// Hooks - Inline detour hooking for send/recv
// + IAT patching (kept for KODefender bypass use)
//
// KODefender monitors the wsock32 IAT entries for tampering.
// Solution: inline hook the actual wsock32.send/recv functions
// by overwriting their first 5 bytes with JMP to our hooks.
// The IAT stays untouched, so KODefender's checksum passes.
// ============================================================

namespace Hooks {

    // Original function pointers (trampolines)
    typedef int (WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WINAPI* tRecv)(SOCKET s, char* buf, int len, int flags);

    inline tSend oSend = nullptr;
    inline tRecv oRecv = nullptr;
    inline SOCKET gameSocket = INVALID_SOCKET;

    // Trampoline storage - executable memory holding original bytes + JMP back
    inline uint8_t* sendTrampoline = nullptr;
    inline uint8_t* recvTrampoline = nullptr;

    // Original bytes for unhooking
    inline uint8_t sendOrigBytes[16] = {};
    inline uint8_t recvOrigBytes[16] = {};
    inline DWORD sendFuncAddr = 0;
    inline DWORD recvFuncAddr = 0;

    // Packet log entry
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

    // Send packet through the game's socket using original function
    inline int SendGamePacket(const uint8_t* data, int len) {
        if (oSend && gameSocket != INVALID_SOCKET) {
            return oSend(gameSocket, (const char*)data, len, 0);
        }
        return -1;
    }

    // ---- Hooked functions ----
    // These are called via the inline detour JMP

    int WINAPI hkSend(SOCKET s, const char* buf, int len, int flags);
    int WINAPI hkRecv(SOCKET s, char* buf, int len, int flags);

    // ---- Inline Detour Engine ----

    // Calculate how many bytes we need to copy for a clean trampoline.
    // We need at least 5 bytes for the JMP, but we can't split an instruction.
    // This simple length disassembler handles common x86 prologues.
    inline int GetInstructionLength(uint8_t* addr) {
        uint8_t op = *addr;

        // Common prologue patterns:
        // PUSH EBP = 0x55 (1 byte)
        // MOV EBP, ESP = 0x8B 0xEC or 0x89 0xE5 (2 bytes)
        // SUB ESP, imm8 = 0x83 0xEC xx (3 bytes)
        // SUB ESP, imm32 = 0x81 0xEC xx xx xx xx (6 bytes)
        // PUSH reg = 0x50-0x57 (1 byte)
        // MOV reg, imm32 = 0xB8-0xBF (5 bytes)
        // MOV [ESP+xx], reg = various (3-4 bytes)
        // NOP = 0x90 (1 byte)
        // MOV EAX, [addr] = 0xA1 (5 bytes)
        // JMP rel8 = 0xEB (2 bytes)
        // JMP rel32 = 0xE9 (5 bytes)
        // RET = 0xC3 (1 byte)
        // RET imm16 = 0xC2 (3 bytes)
        // INT3 = 0xCC (1 byte)
        // LEA reg, [reg+disp8] = 0x8D 4x xx (3 bytes)
        // MOV reg, [reg] = 0x8B xx (2 bytes) or with SIB/disp

        switch (op) {
            case 0x55: return 1; // PUSH EBP
            case 0x56: return 1; // PUSH ESI
            case 0x57: return 1; // PUSH EDI
            case 0x53: return 1; // PUSH EBX
            case 0x50: return 1; // PUSH EAX
            case 0x51: return 1; // PUSH ECX
            case 0x52: return 1; // PUSH EDX
            case 0x54: return 1; // PUSH ESP
            case 0x90: return 1; // NOP
            case 0xC3: return 1; // RET
            case 0xCC: return 1; // INT3
            case 0xC2: return 3; // RET imm16
            case 0xEB: return 2; // JMP short
            case 0xE9: return 5; // JMP near
            case 0xE8: return 5; // CALL near
            case 0xA1: return 5; // MOV EAX, [imm32]
            case 0xA3: return 5; // MOV [imm32], EAX

            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                return 5; // MOV reg, imm32

            case 0x68: return 5; // PUSH imm32
            case 0x6A: return 2; // PUSH imm8

            case 0x83: return 3; // Various ops with imm8 (SUB ESP, xx / CMP, etc)
            case 0x81: return 6; // Various ops with imm32 (SUB ESP, xxxxxxxx)

            case 0x8B: // MOV reg, r/m32
            case 0x89: // MOV r/m32, reg
            case 0x3B: // CMP reg, r/m32
            case 0x33: // XOR reg, r/m32
            case 0x2B: // SUB reg, r/m32
            case 0x03: // ADD reg, r/m32
            case 0x0B: // OR reg, r/m32
            case 0x23: // AND reg, r/m32
            case 0x85: // TEST r/m32, reg
            {
                uint8_t modrm = *(addr + 1);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;

                if (mod == 3) return 2;           // reg, reg
                if (mod == 0) {
                    if (rm == 5) return 6;        // [disp32]
                    if (rm == 4) return 3;        // [SIB]
                    return 2;                     // [reg]
                }
                if (mod == 1) {
                    if (rm == 4) return 4;        // [SIB+disp8]
                    return 3;                     // [reg+disp8]
                }
                if (mod == 2) {
                    if (rm == 4) return 7;        // [SIB+disp32]
                    return 6;                     // [reg+disp32]
                }
                return 2;
            }

            case 0x8D: // LEA reg, [r/m]
            {
                uint8_t modrm = *(addr + 1);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                if (mod == 1) {
                    if (rm == 4) return 4;
                    return 3;
                }
                if (mod == 2) {
                    if (rm == 4) return 7;
                    return 6;
                }
                if (mod == 0) {
                    if (rm == 5) return 6;
                    if (rm == 4) return 3;
                    return 2;
                }
                return 2;
            }

            case 0xFF: // Various (PUSH r/m, CALL r/m, JMP r/m)
            {
                uint8_t modrm = *(addr + 1);
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                if (mod == 3) return 2;
                if (mod == 0) {
                    if (rm == 5) return 6;
                    if (rm == 4) return 3;
                    return 2;
                }
                if (mod == 1) {
                    if (rm == 4) return 4;
                    return 3;
                }
                if (mod == 2) {
                    if (rm == 4) return 7;
                    return 6;
                }
                return 2;
            }

            default:
                // For safety, assume 1 byte if unknown
                // This is a fallback - the hook will still work for typical prologues
                return 1;
        }
    }

    // Build a trampoline: copy original bytes + JMP back to original function
    inline uint8_t* CreateTrampoline(uint8_t* targetFunc, int& stolenBytes) {
        // Calculate how many bytes we need to steal (minimum 5 for JMP rel32)
        stolenBytes = 0;
        while (stolenBytes < 5) {
            int len = GetInstructionLength(targetFunc + stolenBytes);
            if (len <= 0) {
                // Fallback: assume 5 bytes (risky but usually works for send/recv)
                stolenBytes = 5;
                break;
            }
            stolenBytes += len;
        }

        // Allocate executable memory for trampoline
        // Trampoline = stolen bytes + JMP back to (targetFunc + stolenBytes)
        int trampolineSize = stolenBytes + 5; // +5 for the JMP back
        uint8_t* trampoline = (uint8_t*)VirtualAlloc(nullptr, trampolineSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!trampoline) return nullptr;

        // Copy the original bytes
        memcpy(trampoline, targetFunc, stolenBytes);

        // Write JMP back to original function after stolen bytes
        DWORD jmpBackTarget = (DWORD)targetFunc + stolenBytes;
        trampoline[stolenBytes] = 0xE9; // JMP rel32
        *(DWORD*)(trampoline + stolenBytes + 1) = jmpBackTarget - (DWORD)(trampoline + stolenBytes + 5);

        return trampoline;
    }

    // Place a JMP from target to our hook
    inline bool PlaceDetour(uint8_t* targetFunc, DWORD hookFunc, uint8_t* origBackup, int stolenBytes) {
        DWORD oldProt;
        if (!VirtualProtect(targetFunc, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;

        // Backup original bytes
        memcpy(origBackup, targetFunc, stolenBytes);

        // Write JMP to hook
        targetFunc[0] = 0xE9; // JMP rel32
        *(DWORD*)(targetFunc + 1) = hookFunc - (DWORD)(targetFunc + 5);

        // NOP any remaining stolen bytes
        for (int i = 5; i < stolenBytes; i++)
            targetFunc[i] = 0x90;

        VirtualProtect(targetFunc, stolenBytes, oldProt, &oldProt);
        return true;
    }

    // Restore original bytes (unhook)
    inline bool RemoveDetour(uint8_t* targetFunc, uint8_t* origBackup, int stolenBytes) {
        DWORD oldProt;
        if (!VirtualProtect(targetFunc, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;

        memcpy(targetFunc, origBackup, stolenBytes);

        VirtualProtect(targetFunc, stolenBytes, oldProt, &oldProt);
        return true;
    }

    // Number of stolen bytes for unhooking
    inline int sendStolenBytes = 0;
    inline int recvStolenBytes = 0;

    // ---- Install Inline Hooks on wsock32.send / wsock32.recv ----
    inline bool InstallNetworkHooks() {
        HMODULE hWsock = GetModuleHandleA("wsock32.dll");
        if (!hWsock) {
            // Try loading it
            hWsock = LoadLibraryA("wsock32.dll");
            if (!hWsock) return false;
        }

        // Get actual function addresses in wsock32.dll
        sendFuncAddr = (DWORD)GetProcAddress(hWsock, "send");
        recvFuncAddr = (DWORD)GetProcAddress(hWsock, "recv");

        if (!sendFuncAddr || !recvFuncAddr)
            return false;

        // Create trampolines (copy original prologue + JMP back)
        sendTrampoline = CreateTrampoline((uint8_t*)sendFuncAddr, sendStolenBytes);
        recvTrampoline = CreateTrampoline((uint8_t*)recvFuncAddr, recvStolenBytes);

        if (!sendTrampoline || !recvTrampoline)
            return false;

        // Set original function pointers to trampolines
        oSend = (tSend)sendTrampoline;
        oRecv = (tRecv)recvTrampoline;

        // Place detours: overwrite function start with JMP to our hooks
        bool sendOk = PlaceDetour((uint8_t*)sendFuncAddr, (DWORD)hkSend, sendOrigBytes, sendStolenBytes);
        bool recvOk = PlaceDetour((uint8_t*)recvFuncAddr, (DWORD)hkRecv, recvOrigBytes, recvStolenBytes);

        return sendOk && recvOk;
    }

    // ---- Remove Inline Hooks ----
    inline void RemoveNetworkHooks() {
        if (sendFuncAddr && sendStolenBytes > 0) {
            RemoveDetour((uint8_t*)sendFuncAddr, sendOrigBytes, sendStolenBytes);
        }
        if (recvFuncAddr && recvStolenBytes > 0) {
            RemoveDetour((uint8_t*)recvFuncAddr, recvOrigBytes, recvStolenBytes);
        }
        if (sendTrampoline) {
            VirtualFree(sendTrampoline, 0, MEM_RELEASE);
            sendTrampoline = nullptr;
        }
        if (recvTrampoline) {
            VirtualFree(recvTrampoline, 0, MEM_RELEASE);
            recvTrampoline = nullptr;
        }
        oSend = nullptr;
        oRecv = nullptr;
    }

    // ---- IAT Hook Helper (kept for DefenderBypass use) ----
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

    // ---- Hook function implementations ----
    // Defined after all declarations to avoid forward reference issues

    inline int WINAPI hkSend(SOCKET s, const char* buf, int len, int flags) {
        if (gameSocket == INVALID_SOCKET)
            gameSocket = s;

        {
            std::lock_guard<std::mutex> lock(logMutex);
            PacketLog entry;
            entry.isSend = true;
            entry.timestamp = GetTickCount();
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

    inline int WINAPI hkRecv(SOCKET s, char* buf, int len, int flags) {
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
