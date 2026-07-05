/*
 * Copyright (c) 2026 cormoran
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <cormoran/zmk/custom_settings.h>
#include <zmk/ble.h>

#include "os_detection_internal.h"

/* One pair of settings per BLE profile: "ble_detected/<i>" (last auto-guess,
 * cached across reboots) and "ble_override/<i>" (manual override from the
 * Custom Studio RPC web UI, ZMK_OS_UNKNOWN == AUTO). Written out explicitly
 * per index (rather than generated with LISTIFY) to keep the
 * STRUCT_SECTION_ITERABLE static initializers simple - see the
 * ZMK_CUSTOM_SETTING_RANGE_INT32 pitfall noted in DESIGN.md for why these
 * use ZMK_CUSTOM_SETTING_NO_CONSTRAINT instead of a range constraint. */

#define OS_DETECTION_SETTING_DETECTED(_i)                                                          \
    ZMK_CUSTOM_SETTING_ARRAY_ELEMENT_DEFINE(                                                       \
        os_detection_ble_detected_##_i, "cormoran__os_detection", "ble_detected", _i,              \
        ZMK_BLE_PROFILE_COUNT, ZMK_CUSTOM_SETTING_VALUE_TYPE_INT32,                                \
        ZMK_CUSTOM_SETTING_VALUE_INT32(ZMK_OS_UNKNOWN),                                            \
        ZMK_CUSTOM_SETTING_CONFIDENTIALITY_RPC_PUBLIC, ZMK_CUSTOM_SETTING_PERMISSION_UNSECURE,     \
        ZMK_CUSTOM_SETTING_PERMISSION_UNSECURE, ZMK_CUSTOM_SETTING_NO_CONSTRAINT)

#define OS_DETECTION_SETTING_OVERRIDE(_i)                                                          \
    ZMK_CUSTOM_SETTING_ARRAY_ELEMENT_DEFINE(                                                       \
        os_detection_ble_override_##_i, "cormoran__os_detection", "ble_override", _i,              \
        ZMK_BLE_PROFILE_COUNT, ZMK_CUSTOM_SETTING_VALUE_TYPE_INT32,                                \
        ZMK_CUSTOM_SETTING_VALUE_INT32(ZMK_OS_UNKNOWN),                                            \
        ZMK_CUSTOM_SETTING_CONFIDENTIALITY_RPC_PUBLIC, ZMK_CUSTOM_SETTING_PERMISSION_UNSECURE,     \
        ZMK_CUSTOM_SETTING_PERMISSION_UNSECURE, ZMK_CUSTOM_SETTING_NO_CONSTRAINT)

/* CONFIG_ZMK_BLE_PROFILE_COUNT (== CONFIG_BT_MAX_PAIRED, minus split
 * peripherals) defaults to 5; support up to 8 to leave headroom. */
#if ZMK_BLE_PROFILE_COUNT > 0
OS_DETECTION_SETTING_DETECTED(0);
OS_DETECTION_SETTING_OVERRIDE(0);
#endif
#if ZMK_BLE_PROFILE_COUNT > 1
OS_DETECTION_SETTING_DETECTED(1);
OS_DETECTION_SETTING_OVERRIDE(1);
#endif
#if ZMK_BLE_PROFILE_COUNT > 2
OS_DETECTION_SETTING_DETECTED(2);
OS_DETECTION_SETTING_OVERRIDE(2);
#endif
#if ZMK_BLE_PROFILE_COUNT > 3
OS_DETECTION_SETTING_DETECTED(3);
OS_DETECTION_SETTING_OVERRIDE(3);
#endif
#if ZMK_BLE_PROFILE_COUNT > 4
OS_DETECTION_SETTING_DETECTED(4);
OS_DETECTION_SETTING_OVERRIDE(4);
#endif
#if ZMK_BLE_PROFILE_COUNT > 5
OS_DETECTION_SETTING_DETECTED(5);
OS_DETECTION_SETTING_OVERRIDE(5);
#endif
#if ZMK_BLE_PROFILE_COUNT > 6
OS_DETECTION_SETTING_DETECTED(6);
OS_DETECTION_SETTING_OVERRIDE(6);
#endif
#if ZMK_BLE_PROFILE_COUNT > 7
OS_DETECTION_SETTING_DETECTED(7);
OS_DETECTION_SETTING_OVERRIDE(7);
#endif
BUILD_ASSERT(ZMK_BLE_PROFILE_COUNT <= 8,
             "zmk-feature-os-detection only defines settings for up to 8 BLE profiles");

static const struct zmk_custom_setting *find_setting(const char *key, uint8_t profile_index) {
    return zmk_custom_setting_find_array_element("cormoran__os_detection", key, profile_index);
}

static enum zmk_os read_setting(const char *key, uint8_t profile_index) {
    const struct zmk_custom_setting *setting = find_setting(key, profile_index);
    if (!setting) {
        return ZMK_OS_UNKNOWN;
    }
    struct zmk_custom_setting_value value;
    if (zmk_custom_setting_read(setting, &value) != 0) {
        return ZMK_OS_UNKNOWN;
    }
    return (enum zmk_os)value.int32_value;
}

static int write_setting(const char *key, uint8_t profile_index, enum zmk_os os,
                         enum zmk_custom_setting_write_mode mode) {
    const struct zmk_custom_setting *setting = find_setting(key, profile_index);
    if (!setting) {
        return -ENODEV;
    }
    return zmk_custom_setting_write(setting, &ZMK_CUSTOM_SETTING_VALUE_INT32(os), mode);
}

enum zmk_os zmk_os_detection_settings_get_override(uint8_t profile_index) {
    return read_setting("ble_override", profile_index);
}

int zmk_os_detection_settings_set_override(uint8_t profile_index, enum zmk_os os) {
    if (os != ZMK_OS_UNKNOWN && os != ZMK_OS_WINDOWS && os != ZMK_OS_MACOS && os != ZMK_OS_LINUX &&
        os != ZMK_OS_IOS) {
        return -EINVAL;
    }
    return write_setting("ble_override", profile_index, os, ZMK_CUSTOM_SETTING_WRITE_MODE_PERSIST);
}

enum zmk_os zmk_os_detection_settings_get_detected_cache(uint8_t profile_index) {
    return read_setting("ble_detected", profile_index);
}

int zmk_os_detection_settings_set_detected_cache(uint8_t profile_index, enum zmk_os os) {
    return write_setting("ble_detected", profile_index, os, ZMK_CUSTOM_SETTING_WRITE_MODE_PERSIST);
}
