/*
 * Copyright (c) 2026 cormoran
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/logging/log.h>

#include <zmk/event_manager.h>
#include <zmk/events/usb_conn_state_changed.h>

#include "os_detection_internal.h"

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

/* See docs/fingerprints.md: these thresholds are UNVERIFIED placeholders
 * (no packet-level USB capture was possible in the environment this module
 * was written in, on any OS). Replace them once real captures exist -
 * CONFIG_ZMK_OS_DETECTION_TEST_INJECT lets that be done with a unit test
 * alone, no hardware required. */
enum zmk_os zmk_os_classify_usb(const struct usb_fp_stats *stats) {
    if (stats->string_request_count == 0 && !stats->bos_requested) {
        return ZMK_OS_UNKNOWN;
    }

    int distinct_wlength_buckets = 0;
    for (int i = 0; i < USB_FP_WLENGTH_COUNT; i++) {
        if (stats->string_wlength_hist[i] > 0) {
            distinct_wlength_buckets++;
        }
    }
    if (stats->string_wlength_other > 0) {
        distinct_wlength_buckets++;
    }

    /* Windows: re-requests the same string descriptor at several wLengths
     * and also fetches the BOS descriptor. */
    if (stats->bos_requested && distinct_wlength_buckets > 1) {
        return ZMK_OS_WINDOWS;
    }

    /* Linux: fetches each string descriptor once with the full 255-byte
     * buffer, and typically skips BOS. */
    if (stats->string_wlength_hist[USB_FP_WLENGTH_255] > 0 && distinct_wlength_buckets == 1 &&
        !stats->bos_requested) {
        return ZMK_OS_LINUX;
    }

    /* macOS/iOS: mixes in short-wLength descriptor header probes; treated
     * as the fallback for any other observed pattern. */
    if (distinct_wlength_buckets > 0 || stats->bos_requested) {
        return ZMK_OS_MACOS;
    }

    return ZMK_OS_UNKNOWN;
}

static struct usb_fp_stats stats;

static void usb_settle_work_handler(struct k_work *work) {
    enum zmk_os detected = zmk_os_classify_usb(&stats);
    LOG_DBG("os detection: USB fingerprint stats strings=%u other=%u bos=%d",
            stats.string_request_count, stats.string_wlength_other, stats.bos_requested);
    zmk_os_detection_report_usb(detected);
}

static K_WORK_DELAYABLE_DEFINE(usb_settle_work, usb_settle_work_handler);

static void reset_usb_fp_stats(void) { memset(&stats, 0, sizeof(stats)); }

/* Called (via the __wrap_usb_handle_bos hook below, or directly by the
 * CONFIG_ZMK_OS_DETECTION_TEST_INJECT shim) for every standard USB SETUP
 * packet. Observation only - never changes what's returned to the host. */
void zmk_os_detection_observe_setup(const struct usb_setup_packet *setup) {
    if (setup->bRequest == USB_SREQ_SET_ADDRESS) {
        /* Host (re)started enumeration; drop any previous cycle's stats. */
        reset_usb_fp_stats();
        return;
    }

    if (setup->bRequest != USB_SREQ_GET_DESCRIPTOR || !usb_reqtype_is_to_host(setup)) {
        return;
    }

    uint8_t descriptor_type = USB_GET_DESCRIPTOR_TYPE(setup->wValue);
    switch (descriptor_type) {
    case USB_DESC_STRING:
        stats.string_request_count++;
        if (setup->wLength == 255) {
            stats.string_wlength_hist[USB_FP_WLENGTH_255]++;
        } else if (setup->wLength == 2) {
            stats.string_wlength_hist[USB_FP_WLENGTH_2]++;
        } else {
            stats.string_wlength_other++;
        }
        break;
    case USB_DESC_BOS:
        stats.bos_requested = true;
        stats.bos_wlength = setup->wLength;
        break;
    default:
        return; /* not a signal we track; don't restart the debounce timer */
    }

    k_work_reschedule(&usb_settle_work, K_MSEC(CONFIG_ZMK_OS_DETECTION_USB_SETTLE_MS));
}

static int os_detection_usb_listener(const zmk_event_t *eh) {
    const struct zmk_usb_conn_state_changed *ev = as_zmk_usb_conn_state_changed(eh);
    if (ev && ev->conn_state == ZMK_USB_CONN_NONE) {
        k_work_cancel_delayable(&usb_settle_work);
        reset_usb_fp_stats();
    }
    return ZMK_EV_EVENT_BUBBLE;
}

ZMK_LISTENER(os_detection_usb, os_detection_usb_listener);
ZMK_SUBSCRIPTION(os_detection_usb, zmk_usb_conn_state_changed);

#if IS_ENABLED(CONFIG_ZMK_OS_DETECTION_TEST_INJECT)

/* Synthetic SETUP sequences approximating each OS's enumeration pattern, per
 * the (unverified - see docs/fingerprints.md) heuristics above. Used only to
 * unit-test the classifier on native_sim, which has no real USB DC. */
static void inject_setup(uint8_t bRequest, uint8_t descriptor_type, uint16_t wLength) {
    struct usb_setup_packet setup = {
        .bmRequestType = 0x80, /* device-to-host, standard, device recipient */
        .bRequest = bRequest,
        .wValue = (uint16_t)(descriptor_type << 8),
        .wLength = wLength,
    };
    zmk_os_detection_observe_setup(&setup);
}

static void inject_windows_like(void) {
    inject_setup(USB_SREQ_SET_ADDRESS, 0, 0);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 2);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 255);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_BOS, 5);
}

static void inject_macos_like(void) {
    inject_setup(USB_SREQ_SET_ADDRESS, 0, 0);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 2);
}

static void inject_linux_like(void) {
    inject_setup(USB_SREQ_SET_ADDRESS, 0, 0);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 255);
}

/* Run every scenario sequentially in this one process/port-3240 owner,
 * pausing past the settle debounce between each so every scenario gets
 * classified (and logged) before the stats are reset by the next one's
 * SET_ADDRESS. See the ZMK_OS_DETECTION_TEST_INJECT Kconfig help for why
 * this isn't split into one native_sim process per scenario. */
static int os_detection_test_inject_init(void) {
    const uint32_t settle_margin_ms = CONFIG_ZMK_OS_DETECTION_USB_SETTLE_MS + 20;

    inject_windows_like();
    k_sleep(K_MSEC(settle_margin_ms));

    inject_macos_like();
    k_sleep(K_MSEC(settle_margin_ms));

    inject_linux_like();
    k_sleep(K_MSEC(settle_margin_ms));

    return 0;
}

SYS_INIT(os_detection_test_inject_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);

#endif /* CONFIG_ZMK_OS_DETECTION_TEST_INJECT */

/* Always wrap the real hook, TEST_INJECT or not: --wrap=usb_handle_bos is
 * applied unconditionally by CMakeLists.txt whenever this file is compiled,
 * so __wrap_usb_handle_bos must always exist or the link fails. On
 * native_sim there's no real USB DC to generate SETUP packets, but
 * CONFIG_USB_DEVICE_BOS (selected by CONFIG_ZMK_OS_DETECTION_USB) still
 * compiles usb_handle_bos() in, so the wrap target exists there too. */
int __real_usb_handle_bos(struct usb_setup_packet *setup, int32_t *len, uint8_t **data);

int __wrap_usb_handle_bos(struct usb_setup_packet *setup, int32_t *len, uint8_t **data) {
    zmk_os_detection_observe_setup(setup);
    return __real_usb_handle_bos(setup, len, data);
}
