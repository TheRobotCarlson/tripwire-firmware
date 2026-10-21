# LoRa Packet Protocol

AES-128-GCM encrypted, **40 bytes on the wire**:

```
[8B nonce] [16B ciphertext] [16B GCM auth tag]
```

The 8-byte nonce is `[2B device_id][2B boot][4B counter]`, little-endian. `boot` is stored in NVS and bumped on every start, before the first packet; `counter` restarts at 0 each boot and moves the detector to the next boot instead of wrapping. The 12-byte GCM IV is `[4B key prefix][8B nonce]`.

**Why not a plain sequence counter.** Every detector shares the network key, so the IV must be unique across *all* of them, and across reboots. A per-boot counter alone gives detector 1's packet 5 and detector 2's packet 5 the same IV, which in GCM leaks the XOR of the plaintexts and, over enough pairs, the authentication key (NIST SP 800-38D §8). It also makes the gateway reject every packet from a rebooted detector as a replay until the counter climbs past its old value. Putting `device_id` and `boot` in the nonce fixes both.

## Plaintext format (16 bytes)

| Offset | Size | Field | Notes |
|:---|:---|:---|:---|
| 0 | 2 | `seq` | Low 16 bits of the nonce counter, for logs only. Replay checks use the nonce |
| 2 | 1 | `device_id` | 0–255, unique per detector |
| 3 | 1 | `event_type` | `0x00` CLEAR, `0x01` ALARM, `0x02` TELEMETRY (heartbeat) |
| 4 | 1 | `f0_bin` | Harmonic fundamental bin index (`0` on heartbeat) |
| 5 | 1 | `rms_db` | Frame RMS, dBFS + 96 offset (on a heartbeat, the latest frame at send time) |
| 6 | 1 | `vbat_cv` | Battery voltage: `V = 2.50 + vbat_cv × 0.01`, range 2.50–5.05 V |
| 7 | 1 | `fw_major` | Parsed from `esp_app_get_description()` |
| 8 | 1 | `fw_minor` | |
| 9 | 1 | `fw_patch` | |
| 10 | 2 | `uptime_min` | Minutes since boot, clamped to 65535 (~45 days) |
| 12 | 2 | `free_heap_kb` | `esp_get_free_heap_size() / 1024` |
| 14 | 1 | `tx_fail_count` | Monotonic local TX failure counter, clamped to 255 |
| 15 | 1 | `flags` | Bit 0 = low battery (<3.4 V), bit 1 = USB present (reserved) |

Every packet type (CLEAR / ALARM / TELEMETRY) carries the full 16-byte plaintext. Alarm/clear events piggyback telemetry so Home Assistant gets a fresh battery/heap/uptime reading on every state transition, at zero extra airtime.

## Event delivery

### Alarm and clear events

Sent the instant the audio state machine transitions between SAFE and ALARM. These events are latency-sensitive and get **one local retry** on a randomised 150–300 ms backoff if `SX1262->transmit()` returns a local error (SPI busy, TCXO not settled, etc.). The retry reuses the **same nonce and the same ciphertext**, so if the first packet actually made it over the air but was mis-reported locally, the gateway's replay check dedupes the duplicate.

### Telemetry heartbeat

Sent every `CONFIG_BATEAR_TELEMETRY_HEARTBEAT_MIN` minutes (default **30**) during silent periods, with a **±10% uniform jitter** applied per cycle so a fleet of detectors booted together desynchronises instead of colliding on shared airtime.

Heartbeats are **fire-and-forget** — no retry. The next interval carries a fresh snapshot, so retrying would only waste airtime and risk correlated collisions with the main heartbeat wave.

## No ACK, by design

The gateway is a passive receiver. There is no PHY-level acknowledgement:

- `transmit()=OK` only guarantees the bits left the SX1262. The detector cannot know whether the packet was received, decrypted, or dropped in flight.
- Adding ACKs would triple the network's airtime (detector TX → gateway TX ACK → detector RX window), block the gateway from hearing other nodes during its TX burst, and scale poorly past a handful of detectors.
- Instead, **idempotency and reliability come from the nonce**: the gateway tracks the last `(boot, counter)` per detector and discards any packet that is not strictly newer. A higher `boot` is newer whatever its counter, so a rebooted detector is heard at once. Retried packets that arrive twice are dedup'd; a permanently lost packet is covered by the next state transition (for alarm/clear) or the next heartbeat (for telemetry).

## Airtime budget

At SF10 / BW125 / CR4/5 the 40-byte packet is ~535 ms on air (36 bytes was ~494 ms). The default 30 min heartbeat puts each detector at ~1 s/hour of TX time (0.028% duty cycle), leaving generous headroom for the EU 868 MHz 1%/hour cap and essentially unlimited room on the US/AS 915 MHz ISM bands.

## Security features

- **Nonce `(device_id, boot, counter)`** keeps every GCM IV unique, prevents replays and deduplicates retries.
- **GCM auth tag** ensures integrity and authenticity — a tampered or forged packet fails the tag check and is dropped.
- **Sync word** provides RF-level channel isolation so neighbouring batear networks (or unrelated LoRa traffic with a different sync word) never reach the decrypt stage.
