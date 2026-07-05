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

/* All branches below are VERIFIED signatures (real captures on this
 * workspace's rig against an actual Mac, an actual Windows PC, an actual
 * Linux machine, and an actual iPhone - see docs/fingerprints.md). Note BOS
 * being requested does NOT discriminate macOS/iOS from Linux - all three
 * request it once at its minimal header length; only Windows fetches it at
 * more than that. The macOS/iOS-vs-Linux split instead comes from how
 * *string* descriptors are read: macOS/iOS do a short 2-byte header probe
 * then a full re-read for each one, Linux reads each one directly at the
 * full 255-byte buffer with no header probe. */
enum zmk_os zmk_os_classify_usb(const struct usb_fp_stats *stats) {
    if (stats->string_request_count == 0 && !stats->bos_requested) {
        return ZMK_OS_UNKNOWN;
    }

    bool short_probe_seen = stats->string_wlength_hist[USB_FP_WLENGTH_2] > 0;
    bool full_reread_seen = stats->string_wlength_other > 0;

    /* macOS/iOS (VERIFIED, 2026-07-05 real captures): every descriptor -
     * device, each string, configuration - is read as a short 2-byte
     * header probe followed by a full-length re-read. BOS is requested
     * once at its minimal/standard length (sizeof(struct
     * usb_bos_descriptor) == 5), same as Linux, so it isn't used to
     * distinguish those two here. macOS and iOS share this exact
     * descriptor-read pattern; the only observed difference is that iOS
     * sends SET_FEATURE(DEVICE_REMOTE_WAKEUP) after enumerating and real
     * macOS didn't. */
    if (short_probe_seen && full_reread_seen) {
        return stats->remote_wakeup_enabled ? ZMK_OS_IOS : ZMK_OS_MACOS;
    }

    /* Linux (VERIFIED, 2026-07-05 real capture): fetches every string
     * descriptor (including index 0, the language-ID list) directly at the
     * full 255-byte buffer, with no short header probe first. Also
     * requests BOS once at its minimal length (like macOS), and - not yet
     * tracked as a signal here - retries DEVICE_QUALIFIER (descriptor type
     * 0x06) three times, which neither macOS nor Windows did at all. */
    if (stats->string_wlength_hist[USB_FP_WLENGTH_255] > 0 && !short_probe_seen) {
        return ZMK_OS_LINUX;
    }

    /* Windows (VERIFIED, 2026-07-05 real capture): no string descriptors
     * requested at all; device descriptor probed at wLength=64 (not macOS's
     * 8), then configuration and BOS both fetched directly at wLength=255
     * with no short header probe first. Only the BOS-length signal is
     * checked here since it alone disambiguates from the verified macOS/
     * Linux minimal-BOS pattern above. */
    if (stats->bos_requested && stats->bos_wlength > 5) {
        return ZMK_OS_WINDOWS;
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
    LOG_DBG("os detection: SETUP bmRequestType=0x%02x bRequest=0x%02x wValue=0x%04x "
            "wIndex=0x%04x wLength=%u",
            setup->bmRequestType, setup->bRequest, setup->wValue, setup->wIndex, setup->wLength);

    if (setup->bRequest == USB_SREQ_SET_ADDRESS) {
        /* Host (re)started enumeration; drop any previous cycle's stats. */
        reset_usb_fp_stats();
        return;
    }

    if (setup->bRequest == USB_SREQ_SET_FEATURE && !usb_reqtype_is_to_host(setup) &&
        setup->wValue == USB_SFS_REMOTE_WAKEUP) {
        stats.remote_wakeup_enabled = true;
        k_work_reschedule(&usb_settle_work, K_MSEC(CONFIG_ZMK_OS_DETECTION_USB_SETTLE_MS));
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

static void inject_set_feature_remote_wakeup(void) {
    struct usb_setup_packet setup = {
        .bmRequestType = 0x00, /* host-to-device, standard, device recipient */
        .bRequest = USB_SREQ_SET_FEATURE,
        .wValue = USB_SFS_REMOTE_WAKEUP,
    };
    zmk_os_detection_observe_setup(&setup);
}

/* Matches the real capture in docs/fingerprints.md: no string descriptors
 * at all, device descriptor probed at wLength=64 (not macOS's 8) then the
 * full 18, and both configuration and BOS fetched directly at wLength=255
 * (no short header probe first, unlike macOS). Only the BOS wLength is used
 * for classification today; the device-descriptor probe length and the
 * configuration-descriptor request are recorded here for fidelity/future
 * use but aren't tracked signals yet. */
static void inject_windows_like(void) {
    inject_setup(USB_SREQ_SET_ADDRESS, 0, 0);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE, 64);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE, 18);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_CONFIGURATION, 255);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_BOS, 255);
}

/* Matches the real capture in docs/fingerprints.md: short header probe (2
 * bytes) then full re-read for each of 3 string descriptors, then BOS read
 * once at exactly its minimal header length. */
static void inject_macos_like(void) {
    inject_setup(USB_SREQ_SET_ADDRESS, 0, 0);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 2);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 24);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 2);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 24);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 2);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 34);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_BOS, 5);
}

/* Matches the real capture in docs/fingerprints.md: identical descriptor
 * read pattern to inject_macos_like() (short probe then full re-read on
 * every string, minimal BOS), plus a SET_FEATURE(DEVICE_REMOTE_WAKEUP)
 * after enumeration - the one observed difference between a real iPhone
 * and real macOS. */
static void inject_ios_like(void) {
    inject_setup(USB_SREQ_SET_ADDRESS, 0, 0);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE, 8);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE, 18);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 2);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 24);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 2);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 24);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 2);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 34);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_CONFIGURATION, 9);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_CONFIGURATION, 34);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_BOS, 5);
    inject_set_feature_remote_wakeup();
}

/* Matches the real capture in docs/fingerprints.md: device descriptor
 * probed at wLength=64 (same as Windows, not macOS's 8), a single minimal
 * BOS read (same length as macOS - not a discriminating signal),
 * DEVICE_QUALIFIER retried 3 times (not tracked as a signal, included for
 * fidelity), configuration read as header-then-full like macOS, and every
 * string descriptor (including index 0, the language-ID list) read
 * directly at the full 255-byte buffer with no short probe first. */
static void inject_linux_like(void) {
    inject_setup(USB_SREQ_SET_ADDRESS, 0, 0);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE, 64);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE, 18);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_BOS, 5);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE_QUALIFIER, 10);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE_QUALIFIER, 10);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_DEVICE_QUALIFIER, 10);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_CONFIGURATION, 9);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_CONFIGURATION, 34);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 255);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 255);
    inject_setup(USB_SREQ_GET_DESCRIPTOR, USB_DESC_STRING, 255);
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

    inject_ios_like();
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
