#include <Windows.h>
#include <cstdio>
#include <thread>
#include <chrono>

#include "DefenderBypass.h"
#include "Hooks.h"
#include "MemoryScanner.h"
#include "BotUI.h"
#include "../Common/KOStructs.h"
#include "../Common/PacketBuilder.h"
#include "../Common/PatternScanner.h"

// ============================================================
// BlessedKO Bot - DLL Entry Point
// Phase 1: Scanner, Hook, and Bypass validation tool
// v6: Progressive diagnostic hook modes
// ============================================================

static HMODULE g_hModule = nullptr;
static bool g_running = false;
static bool g_hooksInstalled = false;
static bool g_defenderBypassed = false;
static int g_hookMode = 0;  // 0=naked, 1=minimal, 2=full

// ---- Helper: show debug info in UI ----
static void ShowDebugInfo(const char* prefix) {
    char* line = Hooks::debugInfo;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (nl) {
            *nl = 0;
            char logLine[512];
            sprintf_s(logLine, "%s %s", prefix, line);
            BotUI::Log(logLine);
            *nl = '\n';
            line = nl + 1;
        }
        else {
            char logLine[512];
            sprintf_s(logLine, "%s %s", prefix, line);
            BotUI::Log(logLine);
            break;
        }
    }
}

// ---- Button callbacks ----

void OnScanClick() {
    BotUI::Log("[*] Starting memory scan...");
    BotUI::SetStatus("Status: Scanning...");

    auto result = MemScanner::ScanAll();
    BotUI::Log(result.log);

    if (result.success) {
        BotUI::SetStatus("Status: Scan complete");
        BotUI::Log("[+] Scan finished. Check results above.");
    }
    else {
        BotUI::SetStatus("Status: Scan failed");
        BotUI::Log("[-] Scan failed!");
    }
}

void OnHookClick() {
    if (g_hooksInstalled) {
        BotUI::Log("[!] Hooks already installed");
        return;
    }

    const char* modeNames[] = { "NAKED passthrough", "MINIMAL passthrough", "FULL (logging+SEH)" };
    char msg[256];
    sprintf_s(msg, "[*] Installing hooks v6 - Mode %d: %s", g_hookMode, modeNames[g_hookMode]);
    BotUI::Log(msg);

    if (g_hookMode == 0) {
        BotUI::Log("[*] NAKED mode: zero code execution, pure JMP forwarding");
        BotUI::Log("[*] If this crashes, the trampoline mechanism is broken");
        BotUI::Log("[*] If this WORKS, the game will run normally (invisible hook)");
    }

    if (Hooks::InstallNetworkHooks(g_hookMode)) {
        g_hooksInstalled = true;
        ShowDebugInfo("[*]");

        sprintf_s(msg, "[+] Hooks active! Mode %d: %s", g_hookMode, modeNames[g_hookMode]);
        BotUI::Log(msg);
        BotUI::Log("[+] If game is still running - HOOKS WORK!");
        BotUI::Log("[+] Check BlessedBot_debug.log + BlessedBot_hook.log");

        sprintf_s(msg, "Status: Hooks active (v6 mode %d)", g_hookMode);
        BotUI::SetStatus(msg);
    }
    else {
        BotUI::Log("[-] Failed to install hooks!");
        ShowDebugInfo("[-]");
        BotUI::Log("    Send screenshots of logs to me for debugging!");
    }
}

void OnBypassClick() {
    if (g_defenderBypassed) {
        BotUI::Log("[!] Defender already bypassed");
        return;
    }

    BotUI::Log("[*] Bypassing KODefender...");

    HMODULE hDefender = GetModuleHandleA("KODefender.dll");
    if (!hDefender) {
        BotUI::Log("[!] KODefender.dll not loaded - nothing to bypass");
        BotUI::Log("    This is actually good news - no anti-cheat active!");
        g_defenderBypassed = true;
        BotUI::SetStatus("Status: No defender (safe)");
        return;
    }

    BotUI::Log("[*] KODefender found, neutralizing...");

    if (Defender::Install(g_hModule)) {
        g_defenderBypassed = true;
        BotUI::Log("[+] IsDebuggerPresent hooked");
        BotUI::Log("[+] K32EnumProcesses hooked");
        BotUI::Log("[+] K32GetModuleBaseNameA hooked");
        BotUI::Log("[+] ReadProcessMemory hooked");
        BotUI::Log("[+] Detection strings patched");
        BotUI::SetStatus("Status: Defender bypassed");
    }
    else {
        BotUI::Log("[-] Bypass failed!");
    }
}

void OnDumpClick() {
    if (!g_hooksInstalled) {
        BotUI::Log("[!] Install hooks first!");
        return;
    }

    // Show hook stats
    char statsBuf[256];
    Hooks::GetHookStats(statsBuf, sizeof(statsBuf));
    char statsLine[300];
    sprintf_s(statsLine, "[*] Hook stats: %s", statsBuf);
    BotUI::Log(statsLine);

    // Only show packet log in mode 2
    if (g_hookMode < 2) {
        BotUI::Log("[*] Packet capture only available in Mode 2 (FULL)");
        BotUI::Log("[*] Current mode is passthrough - no packets captured");
        return;
    }

    std::lock_guard<std::mutex> lock(Hooks::logMutex);

    char buf[256];
    sprintf_s(buf, "[*] Packet log: %zu packets captured", Hooks::packetLog.size());
    BotUI::Log(buf);

    size_t start = Hooks::packetLog.size() > 20 ? Hooks::packetLog.size() - 20 : 0;
    for (size_t i = start; i < Hooks::packetLog.size(); i++) {
        auto& pkt = Hooks::packetLog[i];
        std::string hex;
        char hexBuf[4];

        size_t showLen = pkt.data.size() > 32 ? 32 : pkt.data.size();
        for (size_t j = 0; j < showLen; j++) {
            sprintf_s(hexBuf, "%02X ", pkt.data[j]);
            hex += hexBuf;
        }
        if (pkt.data.size() > 32) hex += "...";

        sprintf_s(buf, "  %s [%3zu bytes] %s",
            pkt.isSend ? "SEND" : "RECV",
            pkt.data.size(),
            hex.c_str());
        BotUI::Log(buf);

        if (pkt.data.size() >= 3) {
            uint8_t opcode = pkt.data[2];
            const char* opName = "UNKNOWN";
            switch (opcode) {
            case KO::Opcode::WIZ_MOVE:          opName = "WIZ_MOVE"; break;
            case KO::Opcode::WIZ_ATTACK:         opName = "WIZ_ATTACK"; break;
            case KO::Opcode::WIZ_MAGIC_PROCESS:  opName = "WIZ_MAGIC_PROCESS"; break;
            case KO::Opcode::WIZ_HP_CHANGE:      opName = "WIZ_HP_CHANGE"; break;
            case KO::Opcode::WIZ_MSP_CHANGE:     opName = "WIZ_MSP_CHANGE"; break;
            case KO::Opcode::WIZ_EXP_CHANGE:     opName = "WIZ_EXP_CHANGE"; break;
            case KO::Opcode::WIZ_ITEM_PICKUP:    opName = "WIZ_ITEM_PICKUP"; break;
            case KO::Opcode::WIZ_DEAD:           opName = "WIZ_DEAD"; break;
            case KO::Opcode::WIZ_BUFF:           opName = "WIZ_BUFF"; break;
            case KO::Opcode::WIZ_SELECT_TARGET:  opName = "WIZ_SELECT_TARGET"; break;
            case KO::Opcode::WIZ_TARGET_HP:      opName = "WIZ_TARGET_HP"; break;
            }
            if (strcmp(opName, "UNKNOWN") != 0) {
                sprintf_s(buf, "         -> Opcode 0x%02X = %s", opcode, opName);
                BotUI::Log(buf);
            }
        }
    }
}

void OnTestReadClick() {
    BotUI::Log("[*] Testing memory read at known game addresses...");

    HMODULE hGame = GetModuleHandleA(nullptr);
    if (!hGame) {
        BotUI::Log("[-] Cannot get game module!");
        return;
    }

    char buf[512];

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hGame;
    sprintf_s(buf, "[+] DOS magic: 0x%04X (should be 0x5A4D)", dos->e_magic);
    BotUI::Log(buf);

    DWORD testStr = Scanner::FindString(hGame, "KnightOnline");
    if (testStr) {
        std::string s = MemScanner::ReadString(testStr, 32);
        sprintf_s(buf, "[+] Found string at 0x%08X: \"%s\"", testStr, s.c_str());
        BotUI::Log(buf);
    }

    DWORD loginStr = Scanner::FindString(hGame, "LoginUID");
    if (loginStr) {
        sprintf_s(buf, "[+] LoginUID reference at: 0x%08X", loginStr);
        BotUI::Log(buf);
    }

    HMODULE hWsock = GetModuleHandleA("wsock32.dll");
    if (hWsock) {
        sprintf_s(buf, "[+] wsock32.dll at: 0x%08X", (DWORD)hWsock);
        BotUI::Log(buf);

        DWORD sendAddr = MemScanner::ReadMem<DWORD>(KO::IAT::WS_SEND);
        DWORD recvAddr = MemScanner::ReadMem<DWORD>(KO::IAT::WS_RECV);
        sprintf_s(buf, "[+] IAT send() -> 0x%08X", sendAddr);
        BotUI::Log(buf);
        sprintf_s(buf, "[+] IAT recv() -> 0x%08X", recvAddr);
        BotUI::Log(buf);
    }

    BotUI::Log("[+] Memory read test complete");
}

// ---- Main bot thread ----
void BotThread() {
    Sleep(2000);

    BotUI::Create((HINSTANCE)g_hModule);

    BotUI::onScanClick = OnScanClick;
    BotUI::onHookClick = OnHookClick;
    BotUI::onBypassClick = OnBypassClick;
    BotUI::onDumpClick = OnDumpClick;
    BotUI::onTestReadClick = OnTestReadClick;

    BotUI::Log("=== BlessedKO Bot v6 - Diagnostic Build ===");
    BotUI::Log("Progressive Hook Testing");
    BotUI::Log("=========================================");
    BotUI::Log("");
    BotUI::Log("Hook Mode 0: NAKED (pure JMP, zero code)");
    BotUI::Log("  Tests if hot-patch + trampoline work at all");
    BotUI::Log("");
    BotUI::Log("Instructions:");
    BotUI::Log("1. Click 'Bypass Defender' first");
    BotUI::Log("2. Click 'Hook Net' (starts in Mode 0)");
    BotUI::Log("3. If game survives 10+ seconds = SUCCESS");
    BotUI::Log("4. Send me both .log files");
    BotUI::Log("");
    BotUI::Log("[+] Bot DLL loaded successfully!");

    char buf[128];
    sprintf_s(buf, "[+] DLL base: 0x%08X", (DWORD)g_hModule);
    BotUI::Log(buf);

    BotUI::SetStatus("Status: Ready - bypass defender first!");

    BotUI::MessageLoop();
}

// ---- DLL Entry Point ----
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);

        g_running = true;
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            BotThread();
            return 0;
        }, nullptr, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        g_running = false;
        if (g_hooksInstalled) {
            Hooks::RemoveNetworkHooks();
        }
        if (BotUI::hMainWnd) {
            DestroyWindow(BotUI::hMainWnd);
        }
        break;
    }
    return TRUE;
}
