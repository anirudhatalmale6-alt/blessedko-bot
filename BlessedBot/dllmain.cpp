#include <Windows.h>
#include <cstdio>
#include <thread>
#include <chrono>

#include "DefenderBypass.h"
#include "Hooks.h"
#include "PacketParser.h"
#include "GameState.h"
#include "BotEngine.h"
#include "MemoryScanner.h"
#include "BotUI.h"
#include "../Common/KOStructs.h"
#include "../Common/PacketBuilder.h"
#include "../Common/PatternScanner.h"

// ============================================================
// BlessedKO Bot - DLL Entry Point
// Phase 2: Packet parsing, game state, auto-attack/loot
// ============================================================

static HMODULE g_hModule = nullptr;
static bool g_running = false;
static bool g_hooksInstalled = false;
static bool g_defenderBypassed = false;
static bool g_parserConnected = false;

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

// ---- Phase 1 Button callbacks ----

void OnScanClick() {
    BotUI::Log("[*] Starting memory scan...");
    BotUI::SetStatus("Status: Scanning...");
    auto result = MemScanner::ScanAll();
    BotUI::Log(result.log);
    BotUI::SetStatus(result.success ? "Status: Scan complete" : "Status: Scan failed");
}

void OnHookClick() {
    if (g_hooksInstalled) {
        BotUI::Log("[!] Hooks already installed");
        return;
    }

    BotUI::Log("[*] Installing hooks v8 (indirect call-site)...");

    if (Hooks::InstallNetworkHooks()) {
        g_hooksInstalled = true;
        ShowDebugInfo("[*]");

        size_t sendP = 0, recvP = 0;
        for (auto& site : Hooks::patchedSites) {
            if (site.isSend) sendP++; else recvP++;
        }

        char msg[256];
        sprintf_s(msg, "[+] Hooks active! %zu send + %zu recv sites patched", sendP, recvP);
        BotUI::Log(msg);

        // Connect packet parser to hooks
        if (!g_parserConnected) {
            Hooks::onPacket = [](bool isSend, const uint8_t* data, int len) -> bool {
                if (isSend)
                    PacketParser::FeedSend(data, len);
                else
                    PacketParser::FeedRecv(data, len);
                return true; // Allow packet through
            };

            PacketParser::onPacket = [](const PacketParser::ParsedPacket& pkt) {
                GameState::OnPacket(pkt);
            };

            g_parserConnected = true;
            BotUI::Log("[+] Packet parser connected -> GameState tracking LIVE");
        }

        BotUI::Log("[+] Packet capture + parsing LIVE");
        BotUI::SetStatus("Status: Hooks active + parsing");
    }
    else {
        BotUI::Log("[-] No indirect call sites found!");
        ShowDebugInfo("[-]");
        BotUI::SetStatus("Status: Hook failed");
    }
}

void OnBypassClick() {
    if (g_defenderBypassed) {
        BotUI::Log("[!] Defender already bypassed");
        return;
    }

    BotUI::Log("[*] Bypassing KODefender (v2.2)...");

    HMODULE hDefender = GetModuleHandleA("KODefender.dll");
    if (!hDefender) {
        BotUI::Log("[!] KODefender.dll not loaded");
        g_defenderBypassed = true;
        BotUI::SetStatus("Status: No defender");
        return;
    }

    if (Defender::Install(g_hModule)) {
        g_defenderBypassed = true;
        BotUI::Log("[+] Stealth active (PEB unlink + PE erase)");
        BotUI::SetStatus("Status: Stealth active");
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

    char buf[512];

    // Show raw hook stats
    char statsBuf[256];
    Hooks::GetHookStats(statsBuf, sizeof(statsBuf));
    sprintf_s(buf, "[*] %s", statsBuf);
    BotUI::Log(buf);

    // Show parsed packet stats
    sprintf_s(buf, "[*] Parsed: %ld send, %ld recv packets",
        PacketParser::parsedSendCount, PacketParser::parsedRecvCount);
    BotUI::Log(buf);

    // Show last 20 raw packets with decoded opcodes
    std::lock_guard<std::mutex> lock(Hooks::logMutex);
    sprintf_s(buf, "[*] Raw log: %zu packets", Hooks::packetLog.size());
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

        sprintf_s(buf, "  %s [%3zu] %s",
            pkt.isSend ? "S" : "R",
            pkt.data.size(),
            hex.c_str());
        BotUI::Log(buf);
    }
}

void OnTestReadClick() {
    BotUI::Log("[*] Testing memory reads...");
    char buf[256];

    DWORD sendPtr = *(DWORD*)KO::IAT::WS_SEND;
    DWORD recvPtr = *(DWORD*)KO::IAT::WS_RECV;
    uint8_t* sb = (uint8_t*)sendPtr;
    uint8_t* rb = (uint8_t*)recvPtr;

    sprintf_s(buf, "[+] send@0x%08X: %02X %02X %02X | recv@0x%08X: %02X %02X %02X",
        sendPtr, sb[0], sb[1], sb[2], recvPtr, rb[0], rb[1], rb[2]);
    BotUI::Log(buf);
}

// ---- Phase 2 Button callbacks ----

void OnStartBotClick() {
    if (!g_hooksInstalled) {
        BotUI::Log("[!] Hook Net first, then start bot");
        return;
    }
    if (Bot::isRunning) {
        BotUI::Log("[!] Bot already running");
        return;
    }

    Bot::autoAttack = true;
    Bot::autoLoot = true;
    Bot::Start();
    BotUI::Log("[+] Bot STARTED (attack + loot ON)");
    BotUI::Log("[*] Select a target in-game, bot will auto-attack");
    BotUI::SetStatus("Status: BOT RUNNING");
}

void OnStopBotClick() {
    if (!Bot::isRunning) {
        BotUI::Log("[!] Bot not running");
        return;
    }

    Bot::Stop();
    Bot::autoAttack = false;
    Bot::autoLoot = false;
    BotUI::Log("[*] Bot STOPPED");
    BotUI::SetStatus("Status: Bot stopped");
}

void OnAutoAtkClick() {
    Bot::autoAttack = !Bot::autoAttack;
    char buf[64];
    sprintf_s(buf, "[*] Auto-Attack: %s", Bot::autoAttack ? "ON" : "OFF");
    BotUI::Log(buf);
}

void OnAutoLootClick() {
    Bot::autoLoot = !Bot::autoLoot;
    char buf[64];
    sprintf_s(buf, "[*] Auto-Loot: %s", Bot::autoLoot ? "ON" : "OFF");
    BotUI::Log(buf);
}

void OnShowStateClick() {
    char buf[512];
    GameState::GetStateString(buf, sizeof(buf));
    BotUI::Log("--- Game State ---");
    // Split multiline string into UI log lines
    char* line = buf;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (nl) {
            *nl = 0;
            BotUI::Log(line);
            *nl = '\n';
            line = nl + 1;
        }
        else {
            BotUI::Log(line);
            break;
        }
    }

    // Also update the labels
    char label[128];
    sprintf_s(label, "%d / %d", GameState::player.hp, GameState::player.maxHp);
    BotUI::SetHP(label);
    sprintf_s(label, "%d / %d", GameState::player.mp, GameState::player.maxMp);
    BotUI::SetMP(label);
    sprintf_s(label, "%.1f, %.1f, %.1f", GameState::player.x, GameState::player.y, GameState::player.z);
    BotUI::SetPos(label);
    sprintf_s(label, "ID: %d (%d%%)", GameState::targetId, GameState::targetHpPct);
    BotUI::SetTarget(label);
    sprintf_s(label, "%d", GameState::player.zone);
    BotUI::SetZone(label);
    sprintf_s(label, "PID: %d", GameState::player.id);
    BotUI::SetName(label);
}

void OnShowOpcodesClick() {
    BotUI::Log("--- Opcode Frequency (RECV) ---");
    char buf[2048];
    PacketParser::GetOpcodeStats(buf, sizeof(buf), GameState::recvOpcodes);
    char* line = buf;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (nl) {
            *nl = 0;
            BotUI::Log(line);
            *nl = '\n';
            line = nl + 1;
        }
        else {
            BotUI::Log(line);
            break;
        }
    }

    BotUI::Log("--- Opcode Frequency (SEND) ---");
    PacketParser::GetOpcodeStats(buf, sizeof(buf), GameState::sendOpcodes);
    line = buf;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (nl) {
            *nl = 0;
            BotUI::Log(line);
            *nl = '\n';
            line = nl + 1;
        }
        else {
            BotUI::Log(line);
            break;
        }
    }
}

// ---- Main bot thread ----
void BotThread() {
    // Hide our DLL immediately
    Defender::EarlyStealth(g_hModule);

    Sleep(1000);

    BotUI::Create((HINSTANCE)g_hModule);

    // Wire up ALL callbacks
    BotUI::onScanClick = OnScanClick;
    BotUI::onHookClick = OnHookClick;
    BotUI::onBypassClick = OnBypassClick;
    BotUI::onDumpClick = OnDumpClick;
    BotUI::onTestReadClick = OnTestReadClick;
    BotUI::onStartBotClick = OnStartBotClick;
    BotUI::onStopBotClick = OnStopBotClick;
    BotUI::onAutoAtkClick = OnAutoAtkClick;
    BotUI::onAutoLootClick = OnAutoLootClick;
    BotUI::onShowStateClick = OnShowStateClick;
    BotUI::onShowOpcodesClick = OnShowOpcodesClick;

    BotUI::Log("=== BlessedKO Bot v2.0 - Phase 2 ===");
    BotUI::Log("Packet parsing + Game state + Auto-attack");
    BotUI::Log("=======================================");
    BotUI::Log("");
    BotUI::Log("Setup:");
    BotUI::Log("  1. Bypass Defender (clears debug flags)");
    BotUI::Log("  2. Hook Net (installs hooks + parser)");
    BotUI::Log("");
    BotUI::Log("Bot controls:");
    BotUI::Log("  Start Bot  - enables auto-attack + loot");
    BotUI::Log("  Game State - shows HP/MP/pos/target");
    BotUI::Log("  Opcodes    - shows packet frequency");
    BotUI::Log("");
    BotUI::Log("[+] DLL stealth active (PEB unlink + PE erase)");

    BotUI::SetStatus("Status: Ready");

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
        Bot::Stop();
        if (g_hooksInstalled)
            Hooks::RemoveNetworkHooks();
        if (BotUI::hMainWnd)
            DestroyWindow(BotUI::hMainWnd);
        break;
    }
    return TRUE;
}
