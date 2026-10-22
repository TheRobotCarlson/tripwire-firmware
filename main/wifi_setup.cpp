/*
 * wifi_setup.cpp — the gateway's own setup network, for choosing the logger
 * phone's hotspot in the field. See wifi_setup.h.
 *
 * Every DNS query on the setup network is answered with the gateway's
 * address, and every GET returns the setup page, so phones open it by
 * themselves as a captive portal (iOS hotspot-detect, Android generate_204).
 */

#include "wifi_setup.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "lwip/sockets.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>

static const char *TAG = "wifi_setup";

static volatile bool s_active;
static volatile int s_clients;
static httpd_handle_t s_httpd;
static bool s_dns_started;
static bool s_events_registered;
static wifi_setup_save_fn s_on_save;
static char s_dev[33];
static char s_known1[33];
static char s_known2[33];

/* ---------------- DNS: answer every A query with 192.168.4.1 ---------------- */

/* Turn the query in buf[0..n) into its reply, in place. buf needs 16 bytes
 * of room past n. Returns the reply length, or -1 to ignore the packet. */
static int dns_reply(uint8_t *buf, int n)
{
    if (n < 12) return -1;
    /* One question: walk its name labels, then QTYPE + QCLASS. */
    int q = 12;
    while (q < n && buf[q] != 0) {
        if (buf[q] > 63) return -1;
        q += buf[q] + 1;
    }
    q += 5;
    if (q > n) return -1;
    bool one_q = buf[4] == 0 && buf[5] == 1;
    bool type_a = buf[q - 4] == 0 && buf[q - 3] == 1;

    buf[2] = 0x81;               /* response, recursion desired */
    buf[3] = 0x80;               /* recursion available, no error */
    memset(buf + 6, 0, 6);       /* ancount, nscount, arcount */
    int len = q;
    if (one_q && type_a) {
        static const uint8_t ans[16] = {
            0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 168, 4, 1 };
        buf[7] = 1;
        memcpy(buf + len, ans, sizeof(ans));
        len += sizeof(ans);
    }
    return len;
}

static void dns_task(void *arg)
{
    (void)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (sock < 0 || bind(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "DNS socket failed");
        if (sock >= 0) close(sock);
        vTaskDelete(NULL);
        return;
    }

    uint8_t buf[512];
    for (;;) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        int n = recvfrom(sock, buf, sizeof(buf) - 16, 0, reinterpret_cast<struct sockaddr *>(&from), &flen);
        if (!s_active) continue;
        int len = dns_reply(buf, n);
        if (len > 0) sendto(sock, buf, len, 0, reinterpret_cast<struct sockaddr *>(&from), flen);
    }
}

/* ---------------- HTTP: the setup page ---------------- */

static void html_escape(const char *in, char *out, size_t out_sz)
{
    size_t o = 0;
    for (; *in && o + 7 < out_sz; in++) {
        const char *rep = NULL;
        switch (*in) {
            case '&': rep = "&amp;"; break;
            case '<': rep = "&lt;"; break;
            case '>': rep = "&gt;"; break;
            case '"': rep = "&quot;"; break;
            case '\'': rep = "&#39;"; break;
        }
        if (rep) { size_t l = strlen(rep); memcpy(out + o, rep, l); o += l; }
        else out[o++] = *in;
    }
    out[o] = '\0';
}

static const char *PAGE_HEAD =
    "<!doctype html><html><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>trip/wire gateway</title><style>"
    "body{font:17px/1.45 system-ui,-apple-system,sans-serif;margin:0;padding:20px;max-width:480px;color:#1b1d1f;background:#f6f5f1}"
    "h1{font-size:22px;margin:0 0 8px}label{display:block;margin:14px 0 4px;font-size:14px;color:#5d636a}"
    "input{font:inherit;width:100%;box-sizing:border-box;padding:10px;border:1px solid #bbb;border-radius:8px;background:#fff}"
    "button{font:inherit;margin-top:18px;width:100%;padding:12px;border:0;border-radius:8px;background:#1f5f8b;color:#fff}"
    ".n{font-size:14px;color:#5d636a}</style></head><body>";

/* Send `s` HTML-escaped (names are at most 32 bytes). */
static void send_escaped(httpd_req_t *req, const char *s)
{
    char out[200];
    html_escape(s, out, sizeof(out));
    httpd_resp_sendstr_chunk(req, out);
}

static esp_err_t page_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_sendstr_chunk(req, PAGE_HEAD);
    httpd_resp_sendstr_chunk(req, "<h1>Gateway ");
    send_escaped(req, s_dev);
    httpd_resp_sendstr_chunk(req,
        "</h1>"
        "<p>Type the hotspot of the phone that will be the logger phone. The gateway joins it as soon as that hotspot is on.</p>"
        "<form method=\"post\" action=\"/save\">"
        "<label for=\"s\">Hotspot name</label>"
        "<input id=\"s\" name=\"s\" maxlength=\"32\" required autocapitalize=\"off\" autocorrect=\"off\" autocomplete=\"off\" spellcheck=\"false\">"
        "<label for=\"p\">Hotspot password</label>"
        "<input id=\"p\" name=\"p\" maxlength=\"63\" autocapitalize=\"off\" autocorrect=\"off\" autocomplete=\"off\" spellcheck=\"false\">"
        "<button>Save and join</button></form>"
        "<p class=\"n\">On iPhone the hotspot name is the phone's name, in Settings, General, About. The password is in Settings, Personal Hotspot.</p>");
    if (s_known1[0] || s_known2[0]) {
        httpd_resp_sendstr_chunk(req, "<p class=\"n\">It already knows <b>");
        send_escaped(req, s_known1[0] ? s_known1 : s_known2);
        if (s_known1[0] && s_known2[0]) {
            httpd_resp_sendstr_chunk(req, "</b> and <b>");
            send_escaped(req, s_known2);
            httpd_resp_sendstr_chunk(req, "</b>. A new hotspot replaces the older one.</p>");
        } else {
            httpd_resp_sendstr_chunk(req, "</b>, and keeps it as a second choice.</p>");
        }
    }
    httpd_resp_sendstr_chunk(req, "</body></html>");
    return httpd_resp_sendstr_chunk(req, NULL);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Copy form field `key` from an urlencoded body, decoded. */
static bool form_field(const char *body, const char *key, char *out, size_t out_sz)
{
    size_t kl = strlen(key);
    const char *p = body;
    while (p && *p) {
        if (strncmp(p, key, kl) == 0 && p[kl] == '=') {
            p += kl + 1;
            size_t o = 0;
            while (*p && *p != '&' && o + 1 < out_sz) {
                if (*p == '+') { out[o++] = ' '; p++; }
                else if (*p == '%' && hexval(p[1]) >= 0 && hexval(p[2]) >= 0) {
                    out[o++] = (char)(hexval(p[1]) * 16 + hexval(p[2])); p += 3;
                } else out[o++] = *p++;
            }
            out[o] = '\0';
            return true;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    out[0] = '\0';
    return false;
}

static esp_err_t save_post(httpd_req_t *req)
{
    char body[300];
    int total = 0;
    while (total < (int)sizeof(body) - 1 && total < (int)req->content_len) {
        int r = httpd_req_recv(req, body + total, sizeof(body) - 1 - total);
        if (r <= 0) break;
        total += r;
    }
    body[total] = '\0';

    char ssid[33], pass[64];
    form_field(body, "s", ssid, sizeof(ssid));
    form_field(body, "p", pass, sizeof(pass));
    size_t pl = strlen(pass);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_sendstr_chunk(req, PAGE_HEAD);

    if (!ssid[0] || (pl > 0 && pl < 8)) {
        httpd_resp_sendstr_chunk(req, !ssid[0]
            ? "<h1>Check the hotspot</h1><p>The hotspot name is empty.</p>"
            : "<h1>Check the hotspot</h1><p>A hotspot password is at least 8 characters.</p>");
        httpd_resp_sendstr_chunk(req, "<p><a href=\"/\">Try again</a></p></body></html>");
    } else {
        httpd_resp_sendstr_chunk(req, "<h1>Saved</h1><p>The gateway now closes this network and looks for <b>");
        send_escaped(req, ssid);
        httpd_resp_sendstr_chunk(req, "</b>.</p>"
            "<p>Turn that hotspot on. On iPhone, switch on <b>Maximize Compatibility</b> and keep the Personal Hotspot screen open "
            "until the gateway shows up in the logger, about 30 s.</p></body></html>");
        if (s_on_save) s_on_save(ssid, pass);
    }
    return httpd_resp_sendstr_chunk(req, NULL);
}

/* ---------------- AP lifecycle ---------------- */

static void ap_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base; (void)data;
    if (id == WIFI_EVENT_AP_STACONNECTED) s_clients = s_clients + 1;
    else if (id == WIFI_EVENT_AP_STADISCONNECTED && s_clients > 0) s_clients = s_clients - 1;
}

void wifi_setup_start(const char *device_id, const char *known1,
                      const char *known2, wifi_setup_save_fn on_save)
{
    if (s_active) return;
    s_on_save = on_save;
    strncpy(s_dev, device_id, sizeof(s_dev) - 1);
    strncpy(s_known1, known1, sizeof(s_known1) - 1);
    strncpy(s_known2, known2, sizeof(s_known2) - 1);

    if (!s_events_registered) {
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_STACONNECTED, ap_event, NULL);
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_STADISCONNECTED, ap_event, NULL);
        s_events_registered = true;
    }

    wifi_config_t ap = {};
    int l = snprintf(reinterpret_cast<char *>(ap.ap.ssid), sizeof(ap.ap.ssid),
                     "%.26s setup", device_id);
    ap.ap.ssid_len = (uint8_t)(l < (int)sizeof(ap.ap.ssid) ? l : (int)sizeof(ap.ap.ssid) - 1);
    ap.ap.channel = 1;
    ap.ap.authmode = WIFI_AUTH_OPEN;
    ap.ap.max_connection = 2;

    s_clients = 0;
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &ap);

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.lru_purge_enable = true;
    if (httpd_start(&s_httpd, &cfg) == ESP_OK) {
        httpd_uri_t save = {};
        save.uri = "/save"; save.method = HTTP_POST; save.handler = save_post;
        httpd_register_uri_handler(s_httpd, &save);
        httpd_uri_t any = {};
        any.uri = "/*"; any.method = HTTP_GET; any.handler = page_get;
        httpd_register_uri_handler(s_httpd, &any);
    } else {
        ESP_LOGE(TAG, "httpd_start failed");
        s_httpd = NULL;
    }

    if (!s_dns_started) {
        s_dns_started = xTaskCreate(dns_task, "dns", 3072, NULL, 4, NULL) == pdPASS;
    }
    s_active = true;
    ESP_LOGI(TAG, "setup network \"%s\" open", reinterpret_cast<char *>(ap.ap.ssid));
}

void wifi_setup_stop(void)
{
    if (!s_active) return;
    s_active = false;
    if (s_httpd) { httpd_stop(s_httpd); s_httpd = NULL; }
    esp_wifi_set_mode(WIFI_MODE_STA);
    s_clients = 0;
    ESP_LOGI(TAG, "setup network closed");
}

bool wifi_setup_active(void) { return s_active; }
bool wifi_setup_has_client(void) { return s_active && s_clients > 0; }
