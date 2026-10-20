/*
 * tw_codec.c — Tripwire I1 packet and I1a nonce. No platform dependencies
 * beyond tw_gcm_seal / tw_gcm_open.
 */
#include "tw_codec.h"

#include <string.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void tw_nonce_encode(const tw_nonce_t *n, uint8_t out[TW_NONCE_LEN])
{
    put16(out, n->sender_id);
    put16(out + 2, n->boot);
    put32(out + 4, n->counter);
}

void tw_nonce_decode(const uint8_t in[TW_NONCE_LEN], tw_nonce_t *n)
{
    n->sender_id = get16(in);
    n->boot      = get16(in + 2);
    n->counter   = get32(in + 4);
}

void tw_build_iv(const uint8_t key[TW_KEY_LEN], const uint8_t nonce[TW_NONCE_LEN],
                 uint8_t iv[TW_IV_LEN])
{
    memcpy(iv, key, 4);
    memcpy(iv + 4, nonce, TW_NONCE_LEN);
}

int tw_tx_start(tw_tx_t *tx, uint16_t sender_id, uint16_t stored_boot)
{
    if (stored_boot == 0xFFFF) return TW_ERR_BOOT_SPENT;
    tx->sender_id    = sender_id;
    tx->boot         = (uint16_t)(stored_boot + 1);
    tx->next_counter = 0;
    return TW_OK;
}

int tw_tx_take(tw_tx_t *tx, tw_nonce_t *out, bool *persist_boot)
{
    *persist_boot = false;
    out->sender_id = tx->sender_id;
    out->boot      = tx->boot;
    out->counter   = tx->next_counter;
    if (tx->next_counter == 0xFFFFFFFFu) {
        if (tx->boot == 0xFFFF) return TW_ERR_BOOT_SPENT;
        tx->boot++;
        tx->next_counter = 0;
        *persist_boot = true;
    } else {
        tx->next_counter++;
    }
    return TW_OK;
}

void tw_alert_encode(const tw_alert_t *a, uint8_t out[TW_PT_LEN])
{
    put16(out, a->listener_id);
    out[2] = a->type;
    put16(out + 3, a->age_ds);
    out[5]  = a->hops;
    out[6]  = a->f0_bin;
    out[7]  = a->rms_db;
    out[8]  = a->conf;
    out[9]  = a->dur_s;
    out[10] = a->vbat_cv;
    out[11] = a->temp_c;
    out[12] = a->rssi_hint;
    out[13] = a->tag_boot;
    out[14] = a->tag_ctr;
    out[15] = a->flags;
}

void tw_alert_decode(const uint8_t in[TW_PT_LEN], tw_alert_t *a)
{
    a->listener_id = get16(in);
    a->type        = in[2];
    a->age_ds      = get16(in + 3);
    a->hops        = in[5];
    a->f0_bin      = in[6];
    a->rms_db      = in[7];
    a->conf        = in[8];
    a->dur_s       = in[9];
    a->vbat_cv     = in[10];
    a->temp_c      = in[11];
    a->rssi_hint   = in[12];
    a->tag_boot    = in[13];
    a->tag_ctr     = in[14];
    a->flags       = in[15];
}

void tw_alert_stamp_origin(tw_alert_t *a, const tw_nonce_t *n)
{
    a->tag_boot = (uint8_t)n->boot;
    a->tag_ctr  = (uint8_t)n->counter;
}

uint32_t tw_alert_dedup_key(const tw_alert_t *a)
{
    return ((uint32_t)a->listener_id << 16) | ((uint32_t)a->tag_boot << 8) | a->tag_ctr;
}

int tw_seal(const uint8_t key[TW_KEY_LEN], const tw_nonce_t *n,
            const uint8_t pt[TW_PT_LEN], uint8_t pkt[TW_PACKET_LEN])
{
    uint8_t iv[TW_IV_LEN];
    tw_nonce_encode(n, pkt);
    tw_build_iv(key, pkt, iv);
    if (tw_gcm_seal(key, iv, pt, TW_PT_LEN, pkt + TW_NONCE_LEN,
                    pkt + TW_NONCE_LEN + TW_PT_LEN) != 0) {
        return TW_ERR_CRYPTO;
    }
    return TW_OK;
}

int tw_open(const uint8_t key[TW_KEY_LEN], const uint8_t pkt[TW_PACKET_LEN],
            tw_nonce_t *n_out, uint8_t pt_out[TW_PT_LEN])
{
    uint8_t iv[TW_IV_LEN];
    tw_build_iv(key, pkt, iv);
    if (tw_gcm_open(key, iv, pkt + TW_NONCE_LEN, TW_PT_LEN,
                    pkt + TW_NONCE_LEN + TW_PT_LEN, pt_out) != 0) {
        return TW_ERR_CRYPTO;
    }
    if (n_out) tw_nonce_decode(pkt, n_out);
    return TW_OK;
}

int tw_relay(const uint8_t key[TW_KEY_LEN], const uint8_t in[TW_PACKET_LEN],
             const tw_nonce_t *relay_nonce, uint16_t hold_ds, int rssi_dbm,
             uint8_t out[TW_PACKET_LEN], tw_alert_t *alert_out)
{
    uint8_t pt[TW_PT_LEN];
    int rc = tw_open(key, in, NULL, pt);
    if (rc != TW_OK) return rc;

    tw_alert_t a;
    tw_alert_decode(pt, &a);

    uint32_t age = (uint32_t)a.age_ds + hold_ds;
    a.age_ds = age > 0xFFFF ? 0xFFFF : (uint16_t)age;
    if (a.hops < TW_HOPS_MAX) a.hops++;

    int link = -rssi_dbm;
    if (link < 1) link = 1;
    if (link > 255) link = 255;
    if ((uint8_t)link > a.rssi_hint) a.rssi_hint = (uint8_t)link;

    tw_alert_encode(&a, pt);
    if (alert_out) *alert_out = a;
    return tw_seal(key, relay_nonce, pt, out);
}

int tw_replay_check(tw_replay_t *t, const tw_nonce_t *n)
{
    tw_replay_entry_t *free_slot = NULL;
    for (size_t i = 0; i < t->capacity; i++) {
        tw_replay_entry_t *e = &t->entries[i];
        if (!e->used) {
            if (!free_slot) free_slot = e;
            continue;
        }
        if (e->sender_id != n->sender_id) continue;
        bool newer = n->boot > e->boot || (n->boot == e->boot && n->counter > e->counter);
        if (!newer) return TW_REPLAY_REJECT;
        e->boot = n->boot;
        e->counter = n->counter;
        return TW_REPLAY_ACCEPT;
    }
    if (!free_slot) return TW_REPLAY_FULL;
    free_slot->used = true;
    free_slot->sender_id = n->sender_id;
    free_slot->boot = n->boot;
    free_slot->counter = n->counter;
    return TW_REPLAY_ACCEPT;
}
