#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <mutex>
#include <cmath>
#include <cstdio>
#include "PacketParser.h"
#include "../Common/KOStructs.h"

// ============================================================
// Game State - Track all game state from parsed packets
//
// All data comes from intercepted packets (no memory reads).
// This is 100% safe and undetectable.
// ============================================================

namespace GameState {

    // Player info
    struct Player {
        uint16_t id = 0;
        int32_t  hp = 0;
        int32_t  maxHp = 0;
        int32_t  mp = 0;
        int32_t  maxMp = 0;
        float    x = 0, y = 0, z = 0;
        uint8_t  zone = 0;
        bool     isDead = false;
    };

    // Nearby entity (player, NPC, mob)
    struct Entity {
        uint16_t id = 0;
        uint16_t npcId = 0;     // >0 = NPC/mob, 0 = player
        float    x = 0, y = 0, z = 0;
        uint8_t  hpPct = 100;
        bool     isDead = false;
        DWORD    lastSeen = 0;
    };

    // Loot on ground
    struct LootDrop {
        uint32_t bundleId = 0;
        float    x = 0, z = 0;
        DWORD    dropTime = 0;
    };

    // State
    inline Player player;
    inline uint16_t targetId = 0;
    inline uint8_t  targetHpPct = 0;
    inline bool     targetDead = false;

    inline std::vector<Entity> entities;
    inline std::vector<LootDrop> lootDrops;
    inline std::mutex mtx;

    // Packet counters per opcode (send and recv separate)
    inline volatile LONG sendOpcodes[256] = {};
    inline volatile LONG recvOpcodes[256] = {};

    // Logging
    inline FILE* logFile = nullptr;
    inline void Log(const char* fmt, ...) {
        if (!logFile) fopen_s(&logFile, "BlessedBot_state.log", "a");
        if (logFile) {
            va_list args;
            va_start(args, fmt);
            fprintf(logFile, "[STATE] ");
            vfprintf(logFile, fmt, args);
            va_end(args);
            fflush(logFile);
        }
    }

    // ---- Helpers ----
    inline float Distance2D(float x1, float z1, float x2, float z2) {
        float dx = x2 - x1, dz = z2 - z1;
        return sqrtf(dx * dx + dz * dz);
    }

    inline Entity* FindEntity(uint16_t id) {
        for (auto& e : entities)
            if (e.id == id) return &e;
        return nullptr;
    }

    inline void UpsertEntity(uint16_t id, float x, float y, float z) {
        Entity* e = FindEntity(id);
        if (e) {
            e->x = x; e->y = y; e->z = z;
            e->lastSeen = GetTickCount();
        }
        else {
            Entity ne = {};
            ne.id = id; ne.x = x; ne.y = y; ne.z = z;
            ne.lastSeen = GetTickCount();
            ne.hpPct = 100;
            entities.push_back(ne);
        }
    }

    // Remove entities not updated for 60 seconds
    inline void PruneEntities() {
        DWORD now = GetTickCount();
        auto it = std::remove_if(entities.begin(), entities.end(),
            [now](const Entity& e) { return (now - e.lastSeen) > 60000; });
        entities.erase(it, entities.end());

        // Also prune old loot (>90 seconds)
        auto lit = std::remove_if(lootDrops.begin(), lootDrops.end(),
            [now](const LootDrop& d) { return (now - d.dropTime) > 90000; });
        lootDrops.erase(lit, lootDrops.end());
    }

    // Find nearest alive entity within range
    inline Entity* FindNearest(float range, bool npcsOnly = true) {
        Entity* best = nullptr;
        float bestDist = range;
        for (auto& e : entities) {
            if (e.isDead) continue;
            if (npcsOnly && e.npcId == 0) continue;
            float d = Distance2D(player.x, player.z, e.x, e.z);
            if (d < bestDist) {
                bestDist = d;
                best = &e;
            }
        }
        return best;
    }

    // ================================================================
    // Packet Handler - decode each packet and update state
    // ================================================================
    inline void OnPacket(const PacketParser::ParsedPacket& pkt) {
        // Count opcodes
        if (pkt.isSend)
            InterlockedIncrement(&sendOpcodes[pkt.opcode]);
        else
            InterlockedIncrement(&recvOpcodes[pkt.opcode]);

        const uint8_t* d = pkt.payload;
        size_t len = pkt.payloadLen;

        // ---- Process SENT packets ----
        if (pkt.isSend) {
            switch (pkt.opcode) {

            case KO::Opcode::WIZ_SELECT_TARGET:
                // SEND: [targetId:2]
                if (len >= 2) {
                    std::lock_guard<std::mutex> lock(mtx);
                    targetId = d[0] | (d[1] << 8);
                    targetHpPct = 100;
                    targetDead = false;
                }
                break;
            }
            return; // Don't process sent packets further
        }

        // ---- Process RECEIVED packets ----
        std::lock_guard<std::mutex> lock(mtx);

        switch (pkt.opcode) {

        case KO::Opcode::WIZ_MYINFO:
            // First packet after login - contains player info
            // Format varies by server, but typically:
            // [id:2] [name:str] [nation:1] [race:1] [class:2] [level:1]
            // [hp:2] [maxHp:2] [mp:2] [maxMp:2] [x:2] [y:2] [z:2] ...
            if (len >= 2) {
                player.id = d[0] | (d[1] << 8);
                Log("Player ID: %d\n", player.id);
            }
            break;

        case KO::Opcode::WIZ_HP_CHANGE:
            // [id:2] [hp:4] or [currentHp:2] [maxHp:2] [attacker:2]
            // Standard USKO: [id:2] [currentHp:int32]
            if (len >= 6) {
                uint16_t id = d[0] | (d[1] << 8);
                int32_t hp = d[2] | (d[3] << 8) | (d[4] << 16) | (d[5] << 24);
                if (id == player.id || player.id == 0) {
                    player.hp = hp;
                    // Try to capture maxHp from first positive value
                    if (hp > player.maxHp) player.maxHp = hp;
                }
            }
            break;

        case KO::Opcode::WIZ_MSP_CHANGE:
            if (len >= 6) {
                uint16_t id = d[0] | (d[1] << 8);
                int32_t mp = d[2] | (d[3] << 8) | (d[4] << 16) | (d[5] << 24);
                if (id == player.id || player.id == 0) {
                    player.mp = mp;
                    if (mp > player.maxMp) player.maxMp = mp;
                }
            }
            break;

        case KO::Opcode::WIZ_MOVE:
            // [id:2] [x:u16] [y:u16] [z:u16] [speed:u16] ...
            if (len >= 8) {
                uint16_t id = d[0] | (d[1] << 8);
                float mx = (float)(uint16_t)(d[2] | (d[3] << 8)) / 10.0f;
                float my = (float)(uint16_t)(d[4] | (d[5] << 8)) / 10.0f;
                float mz = (float)(uint16_t)(d[6] | (d[7] << 8)) / 10.0f;

                if (id == player.id) {
                    player.x = mx; player.y = my; player.z = mz;
                }
                else {
                    UpsertEntity(id, mx, my, mz);
                }
            }
            break;

        case KO::Opcode::WIZ_TARGET_HP:
            // [id:2] [hpPct:1] or [id:2] [currentHp:4] [maxHp:4]
            if (len >= 3) {
                uint16_t id = d[0] | (d[1] << 8);
                uint8_t hp = d[2];
                if (id == targetId) {
                    targetHpPct = hp;
                    targetDead = (hp == 0);
                }
                Entity* e = FindEntity(id);
                if (e) {
                    e->hpPct = hp;
                    e->isDead = (hp == 0);
                    e->lastSeen = GetTickCount();
                }
            }
            break;

        case KO::Opcode::WIZ_DEAD:
            if (len >= 2) {
                uint16_t id = d[0] | (d[1] << 8);
                if (id == player.id) {
                    player.isDead = true;
                    Log("Player DIED\n");
                }
                if (id == targetId) {
                    targetDead = true;
                }
                Entity* e = FindEntity(id);
                if (e) e->isDead = true;
            }
            break;

        case KO::Opcode::WIZ_RESURRECT:
            if (len >= 2) {
                uint16_t id = d[0] | (d[1] << 8);
                if (id == player.id) {
                    player.isDead = false;
                    Log("Player RESURRECTED\n");
                }
            }
            break;

        case KO::Opcode::WIZ_ITEM_DROP:
            if (len >= 8) {
                uint32_t bundle = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24);
                float lx = (float)(uint16_t)(d[4] | (d[5] << 8)) / 10.0f;
                float lz = (float)(uint16_t)(d[6] | (d[7] << 8)) / 10.0f;
                LootDrop drop = {};
                drop.bundleId = bundle;
                drop.x = lx; drop.z = lz;
                drop.dropTime = GetTickCount();
                lootDrops.push_back(drop);
            }
            break;

        case KO::Opcode::WIZ_ZONE_CHANGE:
            if (len >= 1) {
                player.zone = d[0];
                // Clear entities on zone change
                entities.clear();
                lootDrops.clear();
                Log("Zone changed to %d\n", player.zone);
            }
            break;
        }
    }

    // Get formatted state string for UI
    inline void GetStateString(char* buf, int bufSize) {
        std::lock_guard<std::mutex> lock(mtx);
        sprintf_s(buf, bufSize,
            "ID: %d | HP: %d/%d | MP: %d/%d\n"
            "Pos: (%.1f, %.1f, %.1f) | Zone: %d\n"
            "Target: %d (HP: %d%%) %s\n"
            "Entities: %zu | Loot: %zu",
            player.id, player.hp, player.maxHp, player.mp, player.maxMp,
            player.x, player.y, player.z, player.zone,
            targetId, targetHpPct, targetDead ? "[DEAD]" : "",
            entities.size(), lootDrops.size());
    }

} // namespace GameState
