/*
 * test_vectors.c — host test of tw_codec against the shared vector file.
 *
 *   make -C components/tw_codec/test        (needs gcc + libssl-dev)
 *
 * i1_vectors.txt here is a byte-identical copy of tripwire-tools/vectors/
 * i1_vectors.txt, which generates it. tripwire-tools' tests check the copy.
 */
#include "tw_codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KV     16
#define MAX_VALS    8
#define LINE_LEN  256

typedef struct {
    char key[32];
    char vals[MAX_VALS][LINE_LEN];
    int  nvals;
} kv_t;

typedef struct {
    char section[32];
    kv_t kv[MAX_KV];
    int  nkv;
} block_t;

static int s_fail, s_checks;

#define CHECK(cond, ...) do { s_checks++; if (!(cond)) { s_fail++; \
    printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
    return s;
}

static const char *get(const block_t *b, const char *k, int i)
{
    for (int j = 0; j < b->nkv; j++)
        if (!strcmp(b->kv[j].key, k)) return i < b->kv[j].nvals ? b->kv[j].vals[i] : NULL;
    return NULL;
}

static int count(const block_t *b, const char *k)
{
    for (int j = 0; j < b->nkv; j++)
        if (!strcmp(b->kv[j].key, k)) return b->kv[j].nvals;
    return 0;
}

static void hex(const char *s, uint8_t *out, size_t n)
{
    if (strlen(s) != 2 * n) { printf("bad hex length for %zu bytes: %s\n", n, s); exit(2); }
    for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
}

static tw_nonce_t nonce_of(const char *s)
{
    unsigned a, b; unsigned long c;
    if (sscanf(s, "%u %u %lu", &a, &b, &c) != 3) { printf("bad nonce: %s\n", s); exit(2); }
    tw_nonce_t n = { (uint16_t)a, (uint16_t)b, (uint32_t)c };
    return n;
}

static tw_alert_t alert_of(const char *s)
{
    unsigned v[14];
    if (sscanf(s, "%u %u %u %u %u %u %u %u %u %u %u %u %u %u", &v[0], &v[1], &v[2], &v[3], &v[4],
               &v[5], &v[6], &v[7], &v[8], &v[9], &v[10], &v[11], &v[12], &v[13]) != 14) {
        printf("bad alert: %s\n", s); exit(2);
    }
    tw_alert_t a = { (uint16_t)v[0], (uint8_t)v[1], (uint16_t)v[2], (uint8_t)v[3], (uint8_t)v[4],
                     (uint8_t)v[5], (uint8_t)v[6], (uint8_t)v[7], (uint8_t)v[8], (uint8_t)v[9],
                     (uint8_t)v[10], (uint8_t)v[11], (uint8_t)v[12], (uint8_t)v[13] };
    return a;
}

static int nblocks;
static block_t *blocks;

static void load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(2); }
    char line[LINE_LEN];
    blocks = calloc(256, sizeof(block_t));
    while (fgets(line, sizeof line, f)) {
        char *s = trim(line);
        if (!*s || *s == '#') continue;
        if (*s == '[') {
            if (nblocks == 256) { printf("too many blocks\n"); exit(2); }
            block_t *b = &blocks[nblocks++];
            snprintf(b->section, sizeof b->section, "%.*s", (int)strcspn(s + 1, "]"), s + 1);
            continue;
        }
        char *eq = strchr(s, '=');
        if (!eq || !nblocks) { printf("bad line: %s\n", s); exit(2); }
        *eq = 0;
        char *k = trim(s), *v = trim(eq + 1);
        block_t *b = &blocks[nblocks - 1];
        kv_t *kv = NULL;
        for (int j = 0; j < b->nkv; j++) if (!strcmp(b->kv[j].key, k)) kv = &b->kv[j];
        if (!kv) { kv = &b->kv[b->nkv++]; snprintf(kv->key, sizeof kv->key, "%s", k); }
        snprintf(kv->vals[kv->nvals++], LINE_LEN, "%s", v);
    }
    fclose(f);
}

static void test_seal(const block_t *b)
{
    const char *name = get(b, "name", 0);
    uint8_t key[16], want_pt[16], want_iv[12], want_pkt[TW_PACKET_LEN], pt[16], iv[12], pkt[TW_PACKET_LEN];
    hex(get(b, "key", 0), key, 16);
    hex(get(b, "plaintext", 0), want_pt, 16);
    hex(get(b, "iv", 0), want_iv, 12);
    hex(get(b, "packet", 0), want_pkt, TW_PACKET_LEN);
    tw_nonce_t n = nonce_of(get(b, "nonce", 0));
    tw_alert_t a = alert_of(get(b, "alert", 0));

    tw_alert_encode(&a, pt);
    CHECK(!memcmp(pt, want_pt, 16), "%s: plaintext", name);
    uint8_t nb[8];
    tw_nonce_encode(&n, nb);
    tw_build_iv(key, nb, iv);
    CHECK(!memcmp(iv, want_iv, 12), "%s: iv", name);
    CHECK(tw_seal(key, &n, pt, pkt) == TW_OK, "%s: seal rc", name);
    CHECK(!memcmp(pkt, want_pkt, TW_PACKET_LEN), "%s: packet", name);

    tw_nonce_t got_n; uint8_t got_pt[16]; tw_alert_t got_a;
    CHECK(tw_open(key, want_pkt, &got_n, got_pt) == TW_OK, "%s: open", name);
    CHECK(got_n.sender_id == n.sender_id && got_n.boot == n.boot && got_n.counter == n.counter,
          "%s: nonce round trip", name);
    tw_alert_decode(got_pt, &got_a);
    CHECK(!memcmp(got_pt, want_pt, 16) && got_a.listener_id == a.listener_id &&
          got_a.age_ds == a.age_ds && got_a.tag_ctr == a.tag_ctr, "%s: alert round trip", name);
}

static void test_relay(const block_t *b)
{
    const char *name = get(b, "name", 0);
    uint8_t key[16], in[TW_PACKET_LEN], want[TW_PACKET_LEN], out[TW_PACKET_LEN], want_pt[16], got_pt[16];
    hex(get(b, "key", 0), key, 16);
    hex(get(b, "input", 0), in, TW_PACKET_LEN);
    hex(get(b, "packet", 0), want, TW_PACKET_LEN);
    tw_nonce_t rn = nonce_of(get(b, "relay_nonce", 0));
    tw_alert_t want_a = alert_of(get(b, "alert", 0)), got_a;
    int hold = atoi(get(b, "hold_ds", 0)), rssi = atoi(get(b, "rssi_dbm", 0));

    CHECK(tw_relay(key, in, &rn, (uint16_t)hold, rssi, out, &got_a) == TW_OK, "%s: relay rc", name);
    tw_alert_encode(&want_a, want_pt);
    tw_alert_encode(&got_a, got_pt);
    CHECK(!memcmp(want_pt, got_pt, 16), "%s: relayed alert fields", name);
    CHECK(!memcmp(out, want, TW_PACKET_LEN), "%s: relayed packet", name);

    uint8_t src_pt[16]; tw_alert_t src;
    tw_open(key, in, NULL, src_pt);
    tw_alert_decode(src_pt, &src);
    CHECK(tw_alert_dedup_key(&src) == tw_alert_dedup_key(&got_a), "%s: dedup key survives", name);
}

static void test_open_fail(const block_t *b)
{
    uint8_t key[16], pkt[TW_PACKET_LEN], pt[16];
    hex(get(b, "key", 0), key, 16);
    hex(get(b, "packet", 0), pkt, TW_PACKET_LEN);
    CHECK(tw_open(key, pkt, NULL, pt) == TW_ERR_CRYPTO, "%s: must not open", get(b, "name", 0));
}

static void test_tx(const block_t *b)
{
    const char *name = get(b, "name", 0);
    tw_tx_t tx;
    const char *start = get(b, "start", 0);
    if (start) {
        unsigned sender, stored; char want[16];
        sscanf(start, "%u %u -> %15s", &sender, &stored, want);
        int rc = tw_tx_start(&tx, (uint16_t)sender, (uint16_t)stored);
        if (!strcmp(want, "error")) { CHECK(rc == TW_ERR_BOOT_SPENT, "%s: start must fail", name); return; }
        CHECK(rc == TW_OK && tx.boot == (unsigned)atoi(want), "%s: start boot", name);
    } else {
        unsigned s, bt; unsigned long c;
        sscanf(get(b, "state", 0), "%u %u %lu", &s, &bt, &c);
        tx.sender_id = (uint16_t)s; tx.boot = (uint16_t)bt; tx.next_counter = (uint32_t)c;
    }
    for (int i = 0; i < count(b, "take"); i++) {
        const char *t = get(b, "take", i);
        tw_nonce_t n; bool persist;
        int rc = tw_tx_take(&tx, &n, &persist);
        if (!strcmp(t, "error")) { CHECK(rc == TW_ERR_BOOT_SPENT, "%s: take #%d must fail", name, i); continue; }
        unsigned s, bt, p; unsigned long c;
        sscanf(t, "%u %u %lu %u", &s, &bt, &c, &p);
        CHECK(rc == TW_OK && n.sender_id == s && n.boot == bt && n.counter == c && persist == (bool)p,
              "%s: take #%d want %s got %u %u %lu %d", name, i, t,
              n.sender_id, n.boot, (unsigned long)n.counter, persist);
    }
}

static void test_replay(const block_t *b)
{
    const char *name = get(b, "name", 0);
    size_t cap = (size_t)atoi(get(b, "capacity", 0));
    tw_replay_entry_t *e = calloc(cap, sizeof *e);
    tw_replay_t t = { e, cap };
    for (int i = 0; i < count(b, "rx"); i++) {
        unsigned s, bt; unsigned long c; int want;
        sscanf(get(b, "rx", i), "%u %u %lu %d", &s, &bt, &c, &want);
        tw_nonce_t n = { (uint16_t)s, (uint16_t)bt, (uint32_t)c };
        int got = tw_replay_check(&t, &n);
        CHECK(got == want, "%s: rx #%d (%s) got %d", name, i, get(b, "rx", i), got);
    }
    free(e);
}

int main(int argc, char **argv)
{
    load(argc > 1 ? argv[1] : "i1_vectors.txt");
    int per[5] = {0};
    const char *names[5] = { "seal", "relay", "open_fail", "tx", "replay" };
    for (int i = 0; i < nblocks; i++) {
        const block_t *b = &blocks[i];
        if      (!strcmp(b->section, "seal"))      { test_seal(b);      per[0]++; }
        else if (!strcmp(b->section, "relay"))     { test_relay(b);     per[1]++; }
        else if (!strcmp(b->section, "open_fail")) { test_open_fail(b); per[2]++; }
        else if (!strcmp(b->section, "tx"))        { test_tx(b);        per[3]++; }
        else if (!strcmp(b->section, "replay"))    { test_replay(b);    per[4]++; }
        else { printf("unknown section [%s]\n", b->section); s_fail++; }
    }
    for (int i = 0; i < 5; i++) {
        printf("%-10s %d vectors\n", names[i], per[i]);
        CHECK(per[i] > 0, "no [%s] vectors", names[i]);
    }
    printf("%d checks, %d failed\n", s_checks, s_fail);
    return s_fail ? 1 : 0;
}
