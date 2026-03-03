#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <cstdio>

// ============================================================
// KODefender Bypass v2 - Zero-Modification Stealth
//
// v1 modified KODefender's IAT + flipped conditional jumps
// → KODefender's periodic integrity scan detected this at ~15s
//
// v2 uses ZERO code/IAT modifications anywhere:
//   1. PEB Anti-Debug: clear BeingDebugged & NtGlobalFlag
//   2. PEB Unlinking: remove our DLL from all loader lists
//   3. PE Header Erasure: wipe our MZ/PE signatures from memory
//   4. VEH + Hardware BPs: intercept API calls without code mods
//
// Modified in KODefender: ZERO bytes
// Modified in game exe: ZERO bytes (network hooks are separate)
// Modified in system DLLs: ZERO bytes
// ============================================================

namespace Defender {

    inline FILE* logFile = nullptr;
    inline HMODULE g_ourModule = nullptr;
    inline PVOID g_vehHandle = nullptr;

    // Hardware breakpoint target addresses
    inline DWORD g_addrIsDebuggerPresent = 0;

    // Original PEB values for logging
    inline BYTE g_origBeingDebugged = 0;
    inline DWORD g_origNtGlobalFlag = 0;

    // ---- Minimal PEB structures for x86 ----
    typedef struct _UNICODE_STR {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STR;

    typedef struct _LDR_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID      DllBase;
        PVOID      EntryPoint;
        ULONG      SizeOfImage;
        UNICODE_STR FullDllName;
        UNICODE_STR BaseDllName;
    } LDR_ENTRY;

    // ---- Logging ----
    inline void Log(const char* fmt, ...) {
        if (!logFile) fopen_s(&logFile, "BlessedBot_debug.log", "a");
        if (logFile) {
            va_list args;
            va_start(args, fmt);
            fprintf(logFile, "[DEF] ");
            vfprintf(logFile, fmt, args);
            va_end(args);
            fflush(logFile);
        }
    }

    // ================================================================
    // Step 1: Clear PEB Anti-Debug Flags
    //
    // PEB is process data, not code. KODefender checksums its own
    // code/IAT but not the PEB data structure.
    // IsDebuggerPresent() literally returns PEB->BeingDebugged.
    // ================================================================
    inline void ClearPEBFlags() {
        DWORD peb = __readfsdword(0x30); // TEB->PEB on x86

        // PEB+0x02: BeingDebugged (BYTE)
        BYTE* pBeingDebugged = (BYTE*)(peb + 0x02);
        g_origBeingDebugged = *pBeingDebugged;
        *pBeingDebugged = 0;
        Log("PEB->BeingDebugged: %d -> 0\n", g_origBeingDebugged);

        // PEB+0x68: NtGlobalFlag (DWORD)
        // Debuggers set FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        DWORD* pNtGlobalFlag = (DWORD*)(peb + 0x68);
        g_origNtGlobalFlag = *pNtGlobalFlag;
        *pNtGlobalFlag = 0;
        Log("PEB->NtGlobalFlag: 0x%08X -> 0\n", g_origNtGlobalFlag);

        // PEB+0x18: ProcessHeap -> clear debug flags in heap header
        DWORD processHeap = *(DWORD*)(peb + 0x18);
        if (processHeap) {
            DWORD oldFlags = *(DWORD*)(processHeap + 0x0C);
            DWORD oldForce = *(DWORD*)(processHeap + 0x10);
            *(DWORD*)(processHeap + 0x0C) = 2;  // HEAP_GROWABLE only
            *(DWORD*)(processHeap + 0x10) = 0;  // ForceFlags = 0
            Log("Heap Flags: 0x%X -> 0x2, ForceFlags: 0x%X -> 0\n", oldFlags, oldForce);
        }
    }

    // ================================================================
    // Step 2: Unlink Our DLL from PEB Loader Lists
    //
    // After unlinking:
    // - EnumProcessModules() won't list our DLL
    // - GetModuleHandle("BlessedBot.dll") returns NULL
    // - Module name scanning can't find us
    // - No code modifications anywhere
    // ================================================================
    inline void UnlinkFromPEB(HMODULE hModule) {
        DWORD peb = __readfsdword(0x30);
        DWORD ldr = *(DWORD*)(peb + 0x0C); // PEB->Ldr

        // InLoadOrderModuleList is at PEB_LDR_DATA+0x0C
        PLIST_ENTRY head = (PLIST_ENTRY)(ldr + 0x0C);

        for (PLIST_ENTRY cur = head->Flink; cur != head; cur = cur->Flink) {
            LDR_ENTRY* entry = (LDR_ENTRY*)cur;

            if (entry->DllBase == (PVOID)hModule) {
                // Log the DLL name before unlinking
                if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
                    char nameBuf[64] = {};
                    WideCharToMultiByte(CP_ACP, 0, entry->BaseDllName.Buffer,
                        entry->BaseDllName.Length / 2, nameBuf, sizeof(nameBuf) - 1, nullptr, nullptr);
                    Log("Unlinking module: %s (base=0x%08X, size=0x%X)\n",
                        nameBuf, (DWORD)hModule, entry->SizeOfImage);
                }

                // Unlink from InLoadOrderModuleList
                entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
                entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;

                // Unlink from InMemoryOrderModuleList
                entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
                entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;

                // Unlink from InInitializationOrderModuleList
                entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;
                entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;

                Log("Unlinked from all 3 PEB loader lists\n");
                return;
            }
        }
        Log("WARNING: Module 0x%08X not found in PEB loader lists!\n", (DWORD)hModule);
    }

    // ================================================================
    // Step 3: Erase PE Header from Memory
    //
    // After DLL is loaded and initialized, the PE header (first 0x1000
    // bytes) is no longer needed. Erasing it prevents:
    // - Memory scanners finding MZ/PE signatures
    // - KODefender identifying our DLL by reading its headers
    // - Any tool from determining our DLL's imports/exports
    // ================================================================
    inline void ErasePEHeader(HMODULE hModule) {
        // Read SizeOfImage before erasing (for logging)
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
        DWORD sizeOfImage = 0;
        if (dos->e_magic == 0x5A4D) { // "MZ"
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);
            if (nt->Signature == 0x00004550) { // "PE\0\0"
                sizeOfImage = nt->OptionalHeader.SizeOfImage;
            }
        }

        DWORD oldProt;
        if (VirtualProtect((void*)hModule, 0x1000, PAGE_READWRITE, &oldProt)) {
            SecureZeroMemory((void*)hModule, 0x1000);
            VirtualProtect((void*)hModule, 0x1000, oldProt, &oldProt);
            Log("PE header erased (0x1000 bytes, image was 0x%X)\n", sizeOfImage);
        }
        else {
            Log("WARNING: VirtualProtect failed on PE header (error %d)\n", GetLastError());
        }
    }

    // ================================================================
    // Step 4: VEH + Hardware Breakpoints
    //
    // Hardware breakpoints use CPU debug registers (DR0-DR3).
    // When the BP address is executed:
    //   - CPU raises EXCEPTION_SINGLE_STEP
    //   - VEH catches it BEFORE the function runs
    //   - We set EAX=return value, EIP=return address, and continue
    //   - ZERO bytes modified in any DLL code
    //
    // DR0 = IsDebuggerPresent (return FALSE)
    // DR1-3 = reserved for future use
    // ================================================================

    static LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS pExInfo) {
        if (pExInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
            return EXCEPTION_CONTINUE_SEARCH;

        DWORD eip = pExInfo->ContextRecord->Eip;

        // Check if this is our IsDebuggerPresent breakpoint
        if (eip == g_addrIsDebuggerPresent && g_addrIsDebuggerPresent != 0) {
            // Skip the function entirely: set return value and return
            pExInfo->ContextRecord->Eax = 0;  // Return FALSE
            // Pop return address from stack
            pExInfo->ContextRecord->Eip = *(DWORD*)(pExInfo->ContextRecord->Esp);
            pExInfo->ContextRecord->Esp += 4;
            // Clear DR6 status bits
            pExInfo->ContextRecord->Dr6 = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Set hardware breakpoint on a single thread
    inline bool SetHWBPOnThread(HANDLE hThread, int reg, DWORD addr) {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(hThread, &ctx))
            return false;

        // Set breakpoint address
        switch (reg) {
        case 0: ctx.Dr0 = addr; break;
        case 1: ctx.Dr1 = addr; break;
        case 2: ctx.Dr2 = addr; break;
        case 3: ctx.Dr3 = addr; break;
        default: return false;
        }

        // DR7: Local enable bit for this register
        // Bits 0,2,4,6 = local enable for DR0,DR1,DR2,DR3
        // Condition = 00 (execution), Length = 00 (1 byte) - these are default (zero)
        ctx.Dr7 |= (1UL << (reg * 2));       // Local enable
        ctx.Dr7 &= ~(0xFUL << (16 + reg * 4)); // Clear condition+length (execution, 1 byte)

        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        return SetThreadContext(hThread, &ctx) != 0;
    }

    // Set hardware breakpoints on ALL threads in the process
    inline int SetHWBPAllThreads(int reg, DWORD addr) {
        DWORD currentTid = GetCurrentThreadId();
        DWORD pid = GetCurrentProcessId();

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            Log("WARNING: CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
            return 0;
        }

        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        int count = 0;
        int total = 0;

        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                total++;

                // For current thread, use special handling
                if (te.th32ThreadID == currentTid) {
                    // Direct register access for current thread
                    CONTEXT ctx = {};
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    // Use NtGetContextThread for current thread
                    // Actually, for current thread we need a different approach
                    // GetThreadContext on current thread handle works
                    HANDLE hSelf = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
                        FALSE, currentTid);
                    if (hSelf) {
                        if (SetHWBPOnThread(hSelf, reg, addr))
                            count++;
                        CloseHandle(hSelf);
                    }
                    continue;
                }

                HANDLE hThread = OpenThread(
                    THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    if (SetHWBPOnThread(hThread, reg, addr))
                        count++;
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            } while (Thread32Next(snap, &te));
        }

        CloseHandle(snap);
        Log("HWBP DR%d = 0x%08X set on %d/%d threads\n", reg, addr, count, total);
        return count;
    }

    inline void InstallHardwareBreakpoints() {
        // Register VEH with highest priority (called first)
        g_vehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
        Log("VEH handler installed: 0x%p\n", g_vehHandle);

        // Get target function addresses
        g_addrIsDebuggerPresent = (DWORD)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "IsDebuggerPresent");
        Log("IsDebuggerPresent at: 0x%08X\n", g_addrIsDebuggerPresent);

        // Set DR0 = IsDebuggerPresent on all threads
        if (g_addrIsDebuggerPresent) {
            SetHWBPAllThreads(0, g_addrIsDebuggerPresent);
        }
    }

    // ================================================================
    // MAIN INSTALL
    // ================================================================
    inline bool Install(HMODULE hOurModule) {
        g_ourModule = hOurModule;

        Log("\n=== DefenderBypass v2 (Zero-Modification) ===\n");

        // Check KODefender presence
        HMODULE hDefender = GetModuleHandleA("KODefender.dll");
        Log("KODefender: %s (0x%08X)\n",
            hDefender ? "LOADED" : "not found", (DWORD)hDefender);

        // Step 1: Clear anti-debug flags in PEB
        Log("\n--- Step 1: PEB Anti-Debug ---\n");
        ClearPEBFlags();

        // Step 2: Unlink our DLL from PEB loader lists
        Log("\n--- Step 2: PEB Unlinking ---\n");
        UnlinkFromPEB(hOurModule);

        // Step 3: Erase our PE header
        Log("\n--- Step 3: PE Header Erasure ---\n");
        ErasePEHeader(hOurModule);

        // Step 4: Hardware breakpoints for runtime API interception
        Log("\n--- Step 4: VEH + Hardware Breakpoints ---\n");
        InstallHardwareBreakpoints();

        Log("\n=== DefenderBypass v2 Summary ===\n");
        Log("KODefender code modified: ZERO bytes\n");
        Log("KODefender IAT modified: ZERO entries\n");
        Log("Game exe code modified: ZERO bytes\n");
        Log("System DLL modified: ZERO bytes\n");
        Log("Stealth techniques: PEB clear + PEB unlink + PE erase + VEH/HWBP\n");
        Log("=== DefenderBypass v2 Complete ===\n\n");

        return true;
    }

} // namespace Defender
