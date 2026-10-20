/*
 * tw_codec.h — Tripwire alert packet (I1) and nonce (I1a), pure C.
 *
 * The contract is the shared test-vector file (canonical copy in
 * tripwire-tools/vectors/i1_vectors.txt, mirrored at test/i1_vectors.txt).
 * The Python codec in tripwire-tools is checked against the same file.
 *
 * Wire format, 40 bytes:
 *   [8 B nonce][16 B ciphertext][16 B GCM tag]
 *
 * Nonce (I1a), little-endian:
 *   [2 B sender_id][2 B boot][4 B counter]
 * sender_id is whoever transmitted THIS copy: the origin listener, or the
 * relay that re-encrypted it. boot is a flash-stored count bumped on every
 * start; counter restarts at 0 each boot and never wraps within one boot
 * (after 0xFFFFFFFF the sender moves to boot + 1). So (key, IV) never repeats
 * across listeners, reboots, counter wrap or relays.
 *
 * GCM IV (12 B) = key[0..3] || nonce[0..7]. No AAD: the nonce is bound by the
 * IV, so a tampered nonce fails the tag.
 *
 * Plaintext (16 B), little-endian:
 *   0  u16 listener_id   origin listener
 *   2  u8  type          0 CLEAR, 1 ALARM, 2 CHECKIN
 *   3  u16 age_ds        tenths of a second since the sound began, +hold per relay
 *   5  u8  hops          +1 per relay, capped at 15
 *   6  u8  f0_bin
 *   7  u8  rms_db
 *   8  u8  conf
 *   9  u8  dur_s
 *   10 u8  vbat_cv       V = 2.50 + 0.01 * value
 *   11 u8  temp_c        degrees C + 40
 *   12 u8  rssi_hint     weakest link so far as -dBm (0 = not relayed yet)
 *   13 u8  tag_boot      origin's boot & 0xFF    } alert identity that
 *   14 u8  tag_ctr       origin's counter & 0xFF } survives re-encryption
 *   15 u8  flags         classifier version / flags (spare)
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TW_KEY_LEN     16
#define TW_NONCE_LEN    8
#define TW_IV_LEN      12
#define TW_PT_LEN      16
#define TW_TAG_LEN     16
#define TW_PACKET_LEN  (TW_NONCE_LEN + TW_PT_LEN + TW_TAG_LEN)

#define TW_TYPE_CLEAR    0
#define TW_TYPE_ALARM    1
#define TW_TYPE_CHECKIN  2

#define TW_HOPS_MAX     15

typedef struct {
    uint16_t sender_id;
    uint16_t boot;
    uint32_t counter;
} tw_nonce_t;

/* Transmit-side nonce state. next_counter is the counter the next packet uses. */
typedef struct {
    uint16_t sender_id;
    uint16_t boot;
    uint32_t next_counter;
} tw_tx_t;

typedef struct {
    uint16_t listener_id;
    uint8_t  type;
    uint16_t age_ds;
    uint8_t  hops;
    uint8_t  f0_bin;
    uint8_t  rms_db;
    uint8_t  conf;
    uint8_t  dur_s;
    uint8_t  vbat_cv;
    uint8_t  temp_c;
    uint8_t  rssi_hint;
    uint8_t  tag_boot;
    uint8_t  tag_ctr;
    uint8_t  flags;
} tw_alert_t;

enum {
    TW_OK              =  0,
    TW_ERR_CRYPTO      = -1,  /* AEAD failure: wrong key, forged or corrupted */
    TW_ERR_BOOT_SPENT  = -2,  /* boot count exhausted: rotate the network key */
    TW_ERR_LEN         = -3,
};

/* ---- nonce (I1a) ---- */
void tw_nonce_encode(const tw_nonce_t *n, uint8_t out[TW_NONCE_LEN]);
void tw_nonce_decode(const uint8_t in[TW_NONCE_LEN], tw_nonce_t *n);
void tw_build_iv(const uint8_t key[TW_KEY_LEN], const uint8_t nonce[TW_NONCE_LEN],
                 uint8_t iv[TW_IV_LEN]);

/* Start-up: stored_boot is the value read from flash (0 if never written).
 * Sets tx->boot = stored_boot + 1, counter 0. The caller MUST persist tx->boot
 * before the first transmit. Fails once boot 0xFFFF has been used. */
int tw_tx_start(tw_tx_t *tx, uint16_t sender_id, uint16_t stored_boot);

/* Take the nonce for the next packet. On counter exhaustion moves to the next
 * boot and sets *persist_boot (the caller must write tx->boot to flash before
 * the following transmit). */
int tw_tx_take(tw_tx_t *tx, tw_nonce_t *out, bool *persist_boot);

/* ---- plaintext (I1) ---- */
void tw_alert_encode(const tw_alert_t *a, uint8_t out[TW_PT_LEN]);
void tw_alert_decode(const uint8_t in[TW_PT_LEN], tw_alert_t *a);

/* Stamp an origin alert's identity from the nonce it is first sent under. */
void tw_alert_stamp_origin(tw_alert_t *a, const tw_nonce_t *n);

/* Dedup key for relays: (origin listener, tag_boot, tag_ctr). */
uint32_t tw_alert_dedup_key(const tw_alert_t *a);

/* ---- envelope ---- */
int tw_seal(const uint8_t key[TW_KEY_LEN], const tw_nonce_t *n,
            const uint8_t pt[TW_PT_LEN], uint8_t pkt[TW_PACKET_LEN]);
int tw_open(const uint8_t key[TW_KEY_LEN], const uint8_t pkt[TW_PACKET_LEN],
            tw_nonce_t *n_out, uint8_t pt_out[TW_PT_LEN]);

/* Relay one received packet: open it, add hold_ds to age, hops + 1, fold the
 * RSSI it was heard at into rssi_hint, and re-seal under the relay's own nonce.
 * alert_out (optional) receives the updated alert. */
int tw_relay(const uint8_t key[TW_KEY_LEN], const uint8_t in[TW_PACKET_LEN],
             const tw_nonce_t *relay_nonce, uint16_t hold_ds, int rssi_dbm,
             uint8_t out[TW_PACKET_LEN], tw_alert_t *alert_out);

/* ---- receiver replay check ---- */
typedef struct {
    uint16_t sender_id;
    uint16_t boot;
    uint32_t counter;
    bool     used;
} tw_replay_entry_t;

typedef struct {
    tw_replay_entry_t *entries;
    size_t             capacity;
} tw_replay_t;

enum { TW_REPLAY_ACCEPT = 1, TW_REPLAY_REJECT = 0, TW_REPLAY_FULL = -1 };

/* Accept iff (boot, counter) is strictly newer than the last accepted from this
 * sender_id; on accept, record it. A reboot (higher boot) is accepted even
 * though its counter starts again at 0. */
int tw_replay_check(tw_replay_t *t, const tw_nonce_t *n);

/* ---- AEAD hook, implemented per platform (PSA on ESP-IDF, OpenSSL on host) ---- */
int tw_gcm_seal(const uint8_t key[TW_KEY_LEN], const uint8_t iv[TW_IV_LEN],
                const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[TW_TAG_LEN]);
int tw_gcm_open(const uint8_t key[TW_KEY_LEN], const uint8_t iv[TW_IV_LEN],
                const uint8_t *ct, size_t len, const uint8_t tag[TW_TAG_LEN], uint8_t *pt);

#ifdef __cplusplus
}
#endif
