/*
 * Copyright (c) 2026 cormoran
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>

#include <zmk/ble.h>

#include "os_detection_internal.h"

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

/* See docs/fingerprints.md for what's real vs. placeholder here. Real
 * captures (2026-07-05) found Windows and Linux/BlueZ produce the *same*
 * GATT read set (report map, HIDS info, report reference, DIS PnP ID, GAP
 * appearance all read by both) - the "Linux reads report map+info but skips
 * DIS/appearance" assumption below turned out to be wrong for the BlueZ
 * version tested. Since read-set alone can't disambiguate them, and
 * Windows is the larger install base, the Windows check is deliberately
 * checked first so this ambiguous case defaults to Windows rather than
 * Linux. The Linux-specific branch is kept for BlueZ configurations that
 * genuinely never touch DIS/appearance, but don't expect it to fire for
 * every real Linux host. */
enum zmk_os zmk_os_classify_ble(const struct ble_fp_stats *stats) {
    if (stats->ancs_or_ams_present) {
        /* ANCS/AMS (Apple Notification Center/Media Service) are exposed by
         * iPhones/iPads pairing with accessories, not by macOS acting as a
         * BLE peripheral - if the opt-in GATT client probe saw them, that's
         * decisive over every other signal, and specifically means iOS. */
        return ZMK_OS_IOS;
    }

    if (stats->report_map_reads == 0 && stats->hids_info_reads == 0 && stats->pnp_id_reads == 0 &&
        stats->appearance_reads == 0) {
        return ZMK_OS_UNKNOWN;
    }

    /* Windows (VERIFIED, 2026-07-05 real capture) reads DIS PnP ID and GAP
     * Appearance in addition to the HIDS report map - checked first since a
     * real Linux/BlueZ capture the same day showed this pattern too (see
     * comment above); ambiguous cases resolve to Windows on purpose. */
    if (stats->pnp_id_reads > 0 && stats->appearance_reads > 0) {
        return ZMK_OS_WINDOWS;
    }

    /* Linux BlueZ's HID-over-GATT profile reads Report Map + HIDS Info +
     * Report Reference descriptors and skips DIS/Appearance - true for some
     * BlueZ configurations, but NOT the one in the 2026-07-05 real capture
     * (which also read PnP ID + Appearance and matched the Windows rule
     * above instead). Only reachable when DIS/Appearance are genuinely
     * absent. */
    if (stats->report_map_reads > 0 && stats->hids_info_reads > 0 && stats->pnp_id_reads == 0) {
        return ZMK_OS_LINUX;
    }

    /* Fallback: some HIDS access happened but didn't match a clearer
     * pattern above. This is also where real iOS lands today (VERIFIED,
     * 2026-07-05 real iPhone capture: only HIDS Report Map was read, same
     * as macOS) since `ancs_or_ams_present` is never actually set - see the
     * comment above `zmk_os_classify_ble()`. Defaulting this ambiguous case
     * to macOS rather than iOS is deliberate (per module owner, 2026-07-05):
     * same reasoning as defaulting the Windows/Linux ambiguity to Windows -
     * pick the platform value more likely to be right/more common when the
     * signals genuinely can't tell them apart. */
    return ZMK_OS_MACOS;
}

static struct ble_fp_stats profile_stats[ZMK_BLE_PROFILE_COUNT];

static int profile_index_for_conn(struct bt_conn *conn) {
    if (!conn) {
        return -1;
    }
    return zmk_ble_profile_index(bt_conn_get_dst(conn));
}

static void classify_and_report(int profile_index) {
    if (profile_index < 0 || profile_index >= ZMK_BLE_PROFILE_COUNT) {
        return;
    }
    const struct ble_fp_stats *stats = &profile_stats[profile_index];
    enum zmk_os detected = zmk_os_classify_ble(stats);
    LOG_DBG("os detection: BLE fingerprint stats profile=%d report_map=%u hids_info=%u "
            "report_ref=%u pnp_id=%u appearance=%u ancs_ams=%d mtu=%u interval=%u -> os=%d",
            profile_index, stats->report_map_reads, stats->hids_info_reads, stats->report_ref_reads,
            stats->pnp_id_reads, stats->appearance_reads, stats->ancs_or_ams_present,
            stats->att_mtu, stats->initial_conn_interval, detected);
    zmk_os_detection_report_ble_detected(profile_index, detected);
}

static bool os_detection_ble_read_authorize(struct bt_conn *conn, const struct bt_gatt_attr *attr) {
    int profile_index = profile_index_for_conn(conn);
    if (profile_index < 0 || profile_index >= ZMK_BLE_PROFILE_COUNT) {
        return true; /* never block access; observation only */
    }

    struct ble_fp_stats *stats = &profile_stats[profile_index];
    char uuid_str[BT_UUID_STR_LEN];
    bt_uuid_to_str(attr->uuid, uuid_str, sizeof(uuid_str));

    if (bt_uuid_cmp(attr->uuid, BT_UUID_HIDS_REPORT_MAP) == 0) {
        stats->report_map_reads++;
        LOG_DBG("os detection: BLE GATT read profile=%d uuid=%s (HIDS Report Map) count=%u",
                profile_index, uuid_str, stats->report_map_reads);
    } else if (bt_uuid_cmp(attr->uuid, BT_UUID_HIDS_INFO) == 0) {
        stats->hids_info_reads++;
        LOG_DBG("os detection: BLE GATT read profile=%d uuid=%s (HIDS Info) count=%u",
                profile_index, uuid_str, stats->hids_info_reads);
    } else if (bt_uuid_cmp(attr->uuid, BT_UUID_HIDS_REPORT) == 0) {
        stats->report_ref_reads++;
        LOG_DBG("os detection: BLE GATT read profile=%d uuid=%s (HIDS Report) count=%u",
                profile_index, uuid_str, stats->report_ref_reads);
    } else if (bt_uuid_cmp(attr->uuid, BT_UUID_DIS_PNP_ID) == 0) {
        stats->pnp_id_reads++;
        LOG_DBG("os detection: BLE GATT read profile=%d uuid=%s (DIS PnP ID) count=%u",
                profile_index, uuid_str, stats->pnp_id_reads);
    } else if (bt_uuid_cmp(attr->uuid, BT_UUID_GAP_APPEARANCE) == 0) {
        stats->appearance_reads++;
        LOG_DBG("os detection: BLE GATT read profile=%d uuid=%s (GAP Appearance) count=%u",
                profile_index, uuid_str, stats->appearance_reads);
    } else {
        LOG_DBG("os detection: BLE GATT read profile=%d uuid=%s (untracked)", profile_index,
                uuid_str);
        return true; /* not a signal we track */
    }

    classify_and_report(profile_index);
    return true;
}

static struct bt_gatt_authorization_cb os_detection_gatt_authorization_cb = {
    .read_authorize = os_detection_ble_read_authorize,
};

static void os_detection_att_mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx) {
    int profile_index = profile_index_for_conn(conn);
    if (profile_index < 0 || profile_index >= ZMK_BLE_PROFILE_COUNT) {
        return;
    }
    profile_stats[profile_index].att_mtu = rx;
}

static struct bt_gatt_cb os_detection_gatt_cb = {
    .att_mtu_updated = os_detection_att_mtu_updated,
};

static void os_detection_conn_connected(struct bt_conn *conn, uint8_t err) {
    if (err) {
        return;
    }
    int profile_index = profile_index_for_conn(conn);
    if (profile_index < 0 || profile_index >= ZMK_BLE_PROFILE_COUNT) {
        return;
    }
    memset(&profile_stats[profile_index], 0, sizeof(profile_stats[profile_index]));

    struct bt_conn_info info;
    if (bt_conn_get_info(conn, &info) == 0 && info.type == BT_CONN_TYPE_LE) {
        profile_stats[profile_index].initial_conn_interval = info.le.interval;
    }

#if IS_ENABLED(CONFIG_ZMK_CUSTOM_SETTINGS)
    /* Adopt the cached guess immediately; re-detection above will correct
     * it in the background if the fingerprint has changed since last time. */
    enum zmk_os cached = zmk_os_detection_settings_get_detected_cache(profile_index);
    if (cached != ZMK_OS_UNKNOWN) {
        zmk_os_detection_report_ble_detected(profile_index, cached);
    }
#endif
}

static void os_detection_conn_param_updated(struct bt_conn *conn, uint16_t interval,
                                            uint16_t latency, uint16_t timeout) {
    int profile_index = profile_index_for_conn(conn);
    if (profile_index < 0 || profile_index >= ZMK_BLE_PROFILE_COUNT) {
        return;
    }
    if (profile_stats[profile_index].initial_conn_interval == 0) {
        profile_stats[profile_index].initial_conn_interval = interval;
    }
}

static struct bt_conn_cb os_detection_conn_cb = {
    .connected = os_detection_conn_connected,
    .le_param_updated = os_detection_conn_param_updated,
};

static int os_detection_ble_init(void) {
    bt_gatt_authorization_cb_register(&os_detection_gatt_authorization_cb);
    bt_gatt_cb_register(&os_detection_gatt_cb);
    bt_conn_cb_register(&os_detection_conn_cb);
    return 0;
}

SYS_INIT(os_detection_ble_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
