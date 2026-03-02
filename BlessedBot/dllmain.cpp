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
// ============================================================

static HMODULE g_hModule = nullptr;
static bool g_running = false;
static bool g_hooksInstalled = false;
static bool g_defenderBypassed = false;

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

    BotUI::Log("[*] Installing network hooks...");

    if (Hooks::InstallNetworkHooks()) {
        g_hooksInstalled = true;
        BotUI::Log("[+] send() hooked successfully");
        BotUI::Log("[+] recv() hooked successfully");
        BotUI::SetStatus("Status: Hooks active");
    }
    else {
        BotUI::Log("[-] Failed to install hooks!");
        BotUI::Log("    Try: Make sure you're in-game (past login screen)");
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

    std::lock_guard<std::mutex> lock(Hooks::logMutex);

    char buf[256];
    sprintf_s(buf, "[*] Packet log: %zu packets captured", Hooks::packetLog.size());
    BotUI::Log(buf);

    // Show last 20 packets
    size_t start = Hooks::packetLog.size() > 20 ? Hooks::packetLog.size() - 20 : 0;
    for (size_t i = start; i < Hooks::packetLog.size(); i++) {
        auto& pkt = Hooks::packetLog[i];
        std::string hex;
        char hexBuf[4];

        // Show first 32 bytes max
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

        // Try to identify the opcode
        if (pkt.data.size() >= 3) {
            uint8_t opcode = pkt.data[2]; // After 2-byte length header
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

    // Test reading the PE header (should always work)
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hGame;
    sprintf_s(buf, "[+] DOS magic: 0x%04X (should be 0x5A4D)", dos->e_magic);
    BotUI::Log(buf);

    // Test reading known strings
    DWORD testStr = Scanner::FindString(hGame, "KnightOnline");
    if (testStr) {
        std::string s = MemScanner::ReadString(testStr, 32);
        sprintf_s(buf, "[+] Found string at 0x%08X: \"%s\"", testStr, s.c_str());
        BotUI::Log(buf);
    }

    // Try to find player name from Option.ini LoginUID
    // The game stores the login ID in memory after reading Option.ini
    DWORD loginStr = Scanner::FindString(hGame, "LoginUID");
    if (loginStr) {
        sprintf_s(buf, "[+] LoginUID reference at: 0x%08X", loginStr);
        BotUI::Log(buf);
    }

    // Check if wsock32 is loaded
    HMODULE hWsock = GetModuleHandleA("wsock32.dll");
    if (hWsock) {
        sprintf_s(buf, "[+] wsock32.dll at: 0x%08X", (DWORD)hWsock);
        BotUI::Log(buf);

        // Read IAT to verify send/recv addresses
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
    // Wait a moment for the game to fully initialize
    Sleep(2000);

    // Create the UI
    BotUI::Create((HINSTANCE)g_hModule);

    // Set up callbacks
    BotUI::onScanClick = OnScanClick;
    BotUI::onHookClick = OnHookClick;
    BotUI::onBypassClick = OnBypassClick;
    BotUI::onDumpClick = OnDumpClick;
    BotUI::onTestReadClick = OnTestReadClick;

    BotUI::Log("=== BlessedKO Bot v1.0 - Phase 1 ===");
    BotUI::Log("Scanner & Hook Validation Tool");
    BotUI::Log("================================");
    BotUI::Log("");
    BotUI::Log("Instructions:");
    BotUI::Log("1. Click 'Bypass Defender' first");
    BotUI::Log("2. Click 'Hook Net' to intercept packets");
    BotUI::Log("3. Click 'Scan Memory' to find game structures");
    BotUI::Log("4. Click 'Test Read' to verify memory access");
    BotUI::Log("5. Play the game normally, then 'Dump Packets'");
    BotUI::Log("");
    BotUI::Log("[+] Bot DLL loaded successfully!");

    char buf[128];
    sprintf_s(buf, "[+] DLL base: 0x%08X", (DWORD)g_hModule);
    BotUI::Log(buf);

    BotUI::SetStatus("Status: Ready - bypass defender first!");

    // Run the message loop
    BotUI::MessageLoop();
}

// ---- DLL Entry Point ----
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);

        // Launch bot in a separate thread
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
