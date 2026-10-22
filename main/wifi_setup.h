/*
 * wifi_setup.h — field setup for the gateway's hotspot (gateway only)
 *
 * While the gateway can't reach any hotspot it knows, it opens its own open
 * WiFi network, "<device_id> setup". A phone that joins it gets a captive
 * page asking for a hotspot name and password; on Save the gateway stores
 * them in NVS, closes the network and joins that hotspot.
 */
#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*wifi_setup_save_fn)(const char *ssid, const char *pass);

/* Requires esp_wifi already started with a default AP netif created. */
void wifi_setup_start(const char *device_id, const char *known1,
                      const char *known2, wifi_setup_save_fn on_save);
void wifi_setup_stop(void);
bool wifi_setup_active(void);
/* True while a phone is joined to the setup network. */
bool wifi_setup_has_client(void);

#ifdef __cplusplus
}
#endif
