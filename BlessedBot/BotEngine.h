#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <cstdio>
#include "GameState.h"
#include "Hooks.h"
#include "../Common/KOStructs.h"
#include "../Common/PacketBuilder.h"

// ============================================================
// Bot Engine - Auto-attack, skill rotation, auto-loot, auto-pot
//
// All actions are packet-based (no memory writes to game).
// Uses the hooked send() to inject packets.
// ============================================================

namespace Bot {

    // ---- State ----
    inline bool isRunning = false;
    inline bool autoAttack = false;
    inline bool autoLoot = false;
    inline bool autoPot = false;
    inline HANDLE hThread = nullptr;

    // ---- Skill slot ----
    struct Skill {
        uint32_t id;
        int      cooldownMs;
        DWORD    lastUsed;
        bool     enabled;
        char     name[32];
    };
    inline std::vector<Skill> skills;

    // ---- Config ----
    inline int attackDelayMs = 1500;   // Between basic attacks
    inline int skillDelayMs = 2000;    // Between skill casts
    inline int lootDelayMs = 500;      // Between loot attempts
    inline int potDelayMs = 2000;      // Between potion uses
    inline float lootRange = 30.0f;    // Auto-loot range
    inline int hpPotPct = 50;          // Use HP pot below this %
    inline int mpPotPct = 30;          // Use MP pot below this %

    // ---- Timers ----
    inline DWORD lastAttack = 0;
    inline DWORD lastSkill = 0;
    inline DWORD lastLoot = 0;
    inline DWORD lastPot = 0;
    inline DWORD lastStatusLog = 0;

    // ---- Log ----
    inline FILE* logFile = nullptr;
    inline void Log(const char* fmt, ...) {
        if (!logFile) fopen_s(&logFile, "BlessedBot_bot.log", "a");
        if (logFile) {
            va_list args;
            va_start(args, fmt);
            fprintf(logFile, "[BOT] ");
            vfprintf(logFile, fmt, args);
            va_end(args);
            fflush(logFile);
        }
    }

    // ---- Send packet with AA 55 framing ----
    inline bool SendKOPacket(KO::Packet& pkt) {
        if (!Hooks::realSend || Hooks::gameSocket == INVALID_SOCKET)
            return false;

        const uint8_t* payload = pkt.Data();
        uint16_t payloadLen = (uint16_t)pkt.Size();

        // Wire format: AA 55 [size:2] [data] 55 AA
        std::vector<uint8_t> wire;
        wire.reserve(payloadLen + 6);
        wire.push_back(0xAA);
        wire.push_back(0x55);
        wire.push_back(payloadLen & 0xFF);
        wire.push_back((payloadLen >> 8) & 0xFF);
        wire.insert(wire.end(), payload, payload + payloadLen);
        wire.push_back(0x55);
        wire.push_back(0xAA);

        int sent = Hooks::realSend(Hooks::gameSocket,
            (const char*)wire.data(), (int)wire.size(), 0);
        return sent > 0;
    }

    // ---- Actions ----

    inline void DoSelectTarget(uint16_t id) {
        KO::Packet pkt = KO::BuildSelectTarget(id);
        if (SendKOPacket(pkt)) {
            Log("Select target -> %d\n", id);
        }
    }

    inline void DoBasicAttack() {
        if (GameState::targetId == 0 || GameState::targetDead) return;

        KO::Packet pkt = KO::BuildAttackPacket(GameState::targetId);
        if (SendKOPacket(pkt)) {
            lastAttack = GetTickCount();
            Log("Basic attack -> target %d\n", GameState::targetId);
        }
    }

    inline void DoCastSkill(Skill& sk) {
        if (GameState::targetId == 0 || GameState::targetDead) return;

        auto& p = GameState::player;
        float tx = p.x, tz = p.z;

        // Try to get target position
        {
            std::lock_guard<std::mutex> lock(GameState::mtx);
            GameState::Entity* e = GameState::FindEntity(GameState::targetId);
            if (e) { tx = e->x; tz = e->z; }
        }

        KO::Packet pkt = KO::BuildSkillPacket(sk.id, GameState::targetId,
            p.x, p.y, p.z, tx, 0, tz);
        if (SendKOPacket(pkt)) {
            sk.lastUsed = GetTickCount();
            lastSkill = GetTickCount();
            Log("Skill %s (ID:%u) -> target %d\n", sk.name, sk.id, GameState::targetId);
        }
    }

    inline void DoLootNearest() {
        std::lock_guard<std::mutex> lock(GameState::mtx);
        auto& p = GameState::player;

        for (auto it = GameState::lootDrops.begin(); it != GameState::lootDrops.end(); ++it) {
            float d = GameState::Distance2D(p.x, p.z, it->x, it->z);
            if (d < lootRange) {
                KO::Packet pkt = KO::BuildLootPacket(it->bundleId);
                if (SendKOPacket(pkt)) {
                    lastLoot = GetTickCount();
                    Log("Loot bundle %u (dist %.1f)\n", it->bundleId, d);
                    GameState::lootDrops.erase(it);
                    return;
                }
            }
        }
    }

    // ---- Main bot loop ----
    inline DWORD WINAPI BotLoop(LPVOID) {
        Log("=== Bot Started ===\n");
        Log("Attack: %s | Loot: %s | Pot: %s\n",
            autoAttack ? "ON" : "OFF",
            autoLoot ? "ON" : "OFF",
            autoPot ? "ON" : "OFF");

        while (isRunning) {
            DWORD now = GetTickCount();

            // Don't act if dead
            if (GameState::player.isDead) {
                Sleep(500);
                continue;
            }

            // Auto-loot (highest priority)
            if (autoLoot && (now - lastLoot) > (DWORD)lootDelayMs) {
                DoLootNearest();
            }

            // Auto-target: find nearest mob if no target or target dead
            if (autoAttack && (GameState::targetId == 0 || GameState::targetDead)) {
                GameState::Entity* nearest = nullptr;
                {
                    std::lock_guard<std::mutex> lock(GameState::mtx);
                    nearest = GameState::FindNearest(50.0f, true);
                }
                if (nearest) {
                    DoSelectTarget(nearest->id);
                    Sleep(300); // Wait for server to acknowledge
                    continue;  // Re-check on next loop iteration
                }
            }

            // Auto-attack / skill
            if (autoAttack && GameState::targetId != 0 && !GameState::targetDead) {
                // Try skill rotation first
                bool usedSkill = false;
                if (!skills.empty() && (now - lastSkill) > (DWORD)skillDelayMs) {
                    for (auto& sk : skills) {
                        if (!sk.enabled) continue;
                        if ((now - sk.lastUsed) < (DWORD)sk.cooldownMs) continue;
                        DoCastSkill(sk);
                        usedSkill = true;
                        break;
                    }
                }

                // Fall back to basic attack
                if (!usedSkill && (now - lastAttack) > (DWORD)attackDelayMs) {
                    DoBasicAttack();
                }
            }

            // Periodic entity cleanup
            static DWORD lastPrune = 0;
            if ((now - lastPrune) > 15000) {
                GameState::PruneEntities();
                lastPrune = now;
            }

            Sleep(100); // 10 ticks/sec
        }

        Log("=== Bot Stopped ===\n");
        return 0;
    }

    // ---- Start / Stop ----
    inline void Start() {
        if (isRunning) return;
        isRunning = true;
        hThread = CreateThread(nullptr, 0, BotLoop, nullptr, 0, nullptr);
    }

    inline void Stop() {
        if (!isRunning) return;
        isRunning = false;
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
            hThread = nullptr;
        }
    }

    // ---- Skill management ----
    inline void AddSkill(uint32_t id, int cooldownMs, const char* name) {
        Skill sk = {};
        sk.id = id;
        sk.cooldownMs = cooldownMs;
        sk.lastUsed = 0;
        sk.enabled = true;
        strncpy_s(sk.name, name, 31);
        skills.push_back(sk);
        Log("Added skill: %s (ID:%u CD:%dms)\n", name, id, cooldownMs);
    }

    inline void ClearSkills() {
        skills.clear();
    }

} // namespace Bot
