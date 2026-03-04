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
// v2.3: Fix 0x38 HP_CHANGE to 3-byte format [flag:1][hp:2]
//       Fix 0x17 TARGET_HP to [id:2][hp:2][attacker:2]
//       Add 0x18 stat handler [max_hp:2][max_mp:2]
//       Track targetId from RECV 0x17 (not SEND 0x41)
//       0x41 uses click coordinates, not entity IDs
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
    inline uint16_t targetHp = 0;       // Raw HP from 0x17
    inline uint16_t targetMaxHp = 0;    // Max seen HP for current target
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

    // Hex-dump a packet to log file (for analyzing unknown opcodes)
    inline void LogPacketHex(const char* tag, uint8_t opcode, bool isSend,
        const uint8_t* data, size_t len) {
        if (!logFile) fopen_s(&logFile, "BlessedBot_state.log", "a");
        if (!logFile) return;
        fprintf(logFile, "[HEX] %s %s 0x%02X (%zu): ",
            tag, isSend ? "S" : "R", opcode, len);
        size_t show = len > 48 ? 48 : len;
        for (size_t i = 0; i < show; i++)
            fprintf(logFile, "%02X ", data[i]);
        if (len > 48) fprintf(logFile, "...");
        fprintf(logFile, "\n");
        fflush(logFile);
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

    // Reset opcode counters (for isolation testing)
    inline void ResetOpcodes() {
        memset((void*)sendOpcodes, 0, sizeof(sendOpcodes));
        memset((void*)recvOpcodes, 0, sizeof(recvOpcodes));
    }

    // ================================================================
    // Packet Handler - decode each packet and update state
    //
    // v2.1 changes:
    //   - Parse SENT MOVE (0x06) for player position
    //   - Auto-detect player ID from RECV MOVE position match
    //   - Parse 0x0B entity IN/OUT (spawn/despawn)
    //   - Hex-log samples of unknown opcodes to state.log
    // ================================================================
    inline void OnPacket(const PacketParser::ParsedPacket& pkt) {
        // Count opcodes
        if (pkt.isSend)
            InterlockedIncrement(&sendOpcodes[pkt.opcode]);
        else
            InterlockedIncrement(&recvOpcodes[pkt.opcode]);

        const uint8_t* d = pkt.payload;
        size_t len = pkt.payloadLen;

        // Hex-log first 3 samples of each non-trivial opcode
        static int hexSamples[256] = {};
        if (pkt.opcode != KO::Opcode::WIZ_MOVE &&
            pkt.opcode != KO::Opcode::WIZ_ROTATE &&
            pkt.opcode != KO::Opcode::WIZ_HEARTBEAT) {
            if (hexSamples[pkt.opcode] < 3) {
                LogPacketHex("SAMPLE", pkt.opcode, pkt.isSend, d, len);
                hexSamples[pkt.opcode]++;
            }
        }

        // ---- Process SENT packets ----
        if (pkt.isSend) {
            std::lock_guard<std::mutex> lock(mtx);

            switch (pkt.opcode) {

            case KO::Opcode::WIZ_MOVE:
                // SENT MOVE has no player ID (server knows sender)
                // Format: [x:u16/10] [y:u16/10] [z:u16/10] [...]
                if (len >= 6) {
                    player.x = (float)(uint16_t)(d[0] | (d[1] << 8)) / 10.0f;
                    player.y = (float)(uint16_t)(d[2] | (d[3] << 8)) / 10.0f;
                    player.z = (float)(uint16_t)(d[4] | (d[5] << 8)) / 10.0f;
                }
                break;

            // NOTE: WIZ_SELECT_TARGET (0x41) SEND uses click coordinates [0][float:4][0],
            // NOT entity IDs. Target tracking is done via RECV 0x17 instead.
            }
            return;
        }

        // ---- Process RECEIVED packets ----
        std::lock_guard<std::mutex> lock(mtx);

        switch (pkt.opcode) {

        case KO::Opcode::WIZ_MYINFO:
            // Login info - usually missed (sent before hooks installed)
            if (len >= 2) {
                player.id = d[0] | (d[1] << 8);
                Log("Player ID from MYINFO: %d\n", player.id);
            }
            break;

        case KO::Opcode::WIZ_HP_CHANGE:
            // BlessedKO 0x38 = 3-byte format: [flag:1] [hp:2 LE]
            // No entity ID in packet — always refers to own player
            // flag observed: 0x06 = damage taken
            if (len >= 3) {
                uint8_t flag = d[0];
                uint16_t hp = d[1] | (d[2] << 8);
                player.hp = (int32_t)hp;
                if ((int32_t)hp > player.maxHp) player.maxHp = (int32_t)hp;
                player.isDead = (hp == 0);
                Log("HP: %d/%d (flag=0x%02X)\n", hp, player.maxHp, flag);
            }
            break;

        case KO::Opcode::WIZ_MSP_CHANGE:
            // USKO 0x14 - may be different on BlessedKO (unconfirmed)
            if (len >= 6) {
                uint16_t id = d[0] | (d[1] << 8);
                int32_t mp = d[2] | (d[3] << 8) | (d[4] << 16) | (d[5] << 24);
                if (id == player.id) {
                    player.mp = mp;
                    if (mp > player.maxMp) player.maxMp = mp;
                    Log("MP: %d/%d\n", mp, player.maxMp);
                }
            }
            break;

        case KO::Opcode::WIZ_MOVE:
            // RECV: [id:2] [x:u16/10] [y:u16/10] [z:u16/10] ...
            if (len >= 8) {
                uint16_t id = d[0] | (d[1] << 8);
                float mx = (float)(uint16_t)(d[2] | (d[3] << 8)) / 10.0f;
                float my = (float)(uint16_t)(d[4] | (d[5] << 8)) / 10.0f;
                float mz = (float)(uint16_t)(d[6] | (d[7] << 8)) / 10.0f;

                // Auto-detect player ID: match RECV entity with our SENT position
                if (player.id == 0 && player.x != 0.0f) {
                    float dx = fabsf(mx - player.x);
                    float dz = fabsf(mz - player.z);
                    if (dx < 2.0f && dz < 2.0f) {
                        player.id = id;
                        Log("Auto-detected player ID: %d (dx=%.1f dz=%.1f)\n", id, dx, dz);
                    }
                }

                if (id == player.id) {
                    player.x = mx; player.y = my; player.z = mz;
                }
                else {
                    UpsertEntity(id, mx, my, mz);
                }
            }
            break;

        case KO::Opcode::WIZ_NPC_INOUT:
            // Entity spawn/despawn (0x0B) - 2699 recv in Moradon
            // Try common USKO format: [subop:1] [id:2] [if IN: npcId + pos...]
            if (len >= 3) {
                uint8_t subop = d[0];
                uint16_t eid = d[1] | (d[2] << 8);

                if ((subop == 0x01 || subop == 0x03) && len >= 9) {
                    // IN variants: [sub:1][id:2][npcId:2][x:u16][z:u16]
                    uint16_t npcId = d[3] | (d[4] << 8);
                    float ex = (float)(uint16_t)(d[5] | (d[6] << 8)) / 10.0f;
                    float ez = (float)(uint16_t)(d[7] | (d[8] << 8)) / 10.0f;
                    float ey = (len >= 11) ?
                        (float)(uint16_t)(d[9] | (d[10] << 8)) / 10.0f : 0.0f;

                    // Sanity: only add if position looks valid
                    if (ex > 1.0f || ez > 1.0f) {
                        Entity* e = FindEntity(eid);
                        if (e) {
                            e->npcId = npcId; e->x = ex; e->y = ey; e->z = ez;
                            e->isDead = false; e->lastSeen = GetTickCount();
                        }
                        else if (entities.size() < 500) {
                            Entity ne = {};
                            ne.id = eid; ne.npcId = npcId;
                            ne.x = ex; ne.y = ey; ne.z = ez;
                            ne.hpPct = 100; ne.isDead = false;
                            ne.lastSeen = GetTickCount();
                            entities.push_back(ne);
                        }
                    }
                }
                else if (subop == 0x02 || subop == 0x04 || subop == 0x05) {
                    // OUT variants: remove entity
                    auto it = std::remove_if(entities.begin(), entities.end(),
                        [eid](const Entity& e) { return e.id == eid; });
                    entities.erase(it, entities.end());
                }
            }
            break;

        case KO::Opcode::WIZ_TARGET_HP:
            // BlessedKO 0x17 = 6 bytes: [target_id:2] [hp:2] [attacker:2]
            // Server sends this when target is selected or takes damage
            if (len >= 6) {
                uint16_t id = d[0] | (d[1] << 8);
                uint16_t hp = d[2] | (d[3] << 8);
                uint16_t attacker = d[4] | (d[5] << 8);

                // If target changed, reset max HP tracking
                if (id != targetId) {
                    targetMaxHp = hp;
                }

                targetId = id;
                targetHp = hp;
                if (hp > targetMaxHp) targetMaxHp = hp;
                targetDead = (hp == 0);

                // Compute percentage from observed max
                targetHpPct = (targetMaxHp > 0) ?
                    (uint8_t)((uint32_t)hp * 100 / targetMaxHp) : 100;

                Entity* e = FindEntity(id);
                if (e) {
                    e->isDead = (hp == 0);
                    e->lastSeen = GetTickCount();
                }

                Log("Target %d HP: %d/%d (%d%%) attacker: %d\n",
                    id, hp, targetMaxHp, targetHpPct, attacker);
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
                entities.clear();
                lootDrops.clear();
                Log("Zone changed to %d\n", player.zone);
            }
            break;

        case 0x18:
            // BlessedKO stat update: [max_hp:2] [max_mp:2]
            // Observed: F5 13 CD 13 → hp=5109 mp=5069 (base stats pre-buff)
            if (len >= 4) {
                uint16_t mhp = d[0] | (d[1] << 8);
                uint16_t mmp = d[2] | (d[3] << 8);
                // Base max stats (buffs can push actual HP higher)
                if (mhp > 0 && player.maxHp == 0) player.maxHp = mhp;
                if (mmp > 0) player.maxMp = mmp;
                Log("Stats 0x18: maxHP=%d maxMP=%d\n", mhp, mmp);
            }
            break;
        }
    }

    // Get formatted state string for UI
    inline void GetStateString(char* buf, int bufSize) {
        std::lock_guard<std::mutex> lock(mtx);
        sprintf_s(buf, bufSize,
            "ID: %d%s | HP: %d/%d | MP: %d/%d\n"
            "Pos: (%.1f, %.1f, %.1f) | Zone: %d\n"
            "Target: %d (HP: %d/%d = %d%%) %s\n"
            "Entities: %zu | Loot: %zu",
            player.id, player.id == 0 ? " (detecting)" : "",
            player.hp, player.maxHp, player.mp, player.maxMp,
            player.x, player.y, player.z, player.zone,
            targetId, targetHp, targetMaxHp, targetHpPct,
            targetDead ? "[DEAD]" : "",
            entities.size(), lootDrops.size());
    }

} // namespace GameState
