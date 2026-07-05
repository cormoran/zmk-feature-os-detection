# zmk-feature-os-detection

![ZMK Version](https://img.shields.io/badge/ZMK-cormoran%20fork-blue)
[![Test](https://github.com/cormoran/zmk-feature-os-detection/actions/workflows/zmk-module.yml/badge.svg?branch=main)](https://github.com/cormoran/zmk-feature-os-detection/actions/workflows/zmk-module.yml)

A ZMK module that detects the host OS (Windows / macOS·iOS / Linux / unknown)
over **USB** and **BLE**, raises a `zmk_os_changed` event, can auto-switch a
keymap layer per detected OS, and exposes live state + per-BLE-profile
manual overrides through a Custom Studio RPC subsystem and Web UI.

This uses the **unofficial** custom ZMK Studio RPC protocol from
[cormoran/zmk-module-template-with-custom-studio-rpc](https://github.com/cormoran/zmk-module-template-with-custom-studio-rpc).
License: MIT. This module does not reference or reuse any QMK (GPL-2.0)
source code.

## How detection works (short version)

- **USB**: a linker-level hook (`--wrap=usb_handle_bos`) observes every
  standard USB SETUP packet during enumeration - which `GET_DESCRIPTOR`
  requests are sent, at what `wLength`, and whether `GET_DESCRIPTOR(BOS)`
  is requested - without changing anything the host actually receives.
  After a short debounce once enumeration settles, the pattern is
  classified.
- **BLE**: `bt_gatt_authorization_cb_register()` observes which GATT
  characteristics the host reads while pairing/reconnecting (HID Report
  Map, HID Info, DIS PnP ID, GAP Appearance), plus ATT MTU and the initial
  connection interval - always authorizing the read, never blocking it.
- Detection results and any manual BLE override are combined into one
  **effective OS** per transport (override wins), and the effective OS
  for whichever endpoint is currently active is what
  `zmk_os_detection_current()` and the `zmk_os_changed` event report.

**Read [docs/fingerprints.md](docs/fingerprints.md) before relying on this
in production.** The classifier thresholds shipped here are placeholders
based on the general behavior described for each OS, not a verified
capture - see "Known limitations" below.

## Installing

Add this module and the patched ZMK fork it depends on to your
`config/west.yml`:

```yaml
manifest:
  remotes:
    - name: cormoran
      url-base: https://github.com/cormoran
  projects:
    - name: zmk-feature-os-detection
      remote: cormoran
      revision: main
      import: true
    # Required: patched ZMK with Custom Studio RPC support
    - name: zmk
      remote: cormoran
      revision: main+custom-studio-protocol
      import:
        file: app/west.yml
```

`import: true` on `zmk-feature-os-detection` also pulls in its own
dependency, [zmk-feature-custom-settings](https://github.com/cormoran/zmk-feature-custom-settings)
(needed for BLE per-profile override persistence).

## Kconfig

Enable in your `config/<shield>.conf`:

```conf
CONFIG_ZMK_OS_DETECTION=y

# Pick the transport(s) you want detection on. Each requires the matching
# ZMK transport (ZMK_USB / ZMK_BLE) to already be enabled.
CONFIG_ZMK_OS_DETECTION_USB=y
CONFIG_ZMK_OS_DETECTION_BLE=y

# Optional: auto-switch a keymap layer per detected OS (-1 = disabled, default)
CONFIG_ZMK_OS_DETECTION_LAYER_WINDOWS=1
CONFIG_ZMK_OS_DETECTION_LAYER_MACOS=2
CONFIG_ZMK_OS_DETECTION_LAYER_LINUX=3
CONFIG_ZMK_OS_DETECTION_LAYER_UNKNOWN=-1

# Optional: Apple-only ANCS/AMS probe as an extra BLE signal (off by default)
CONFIG_ZMK_OS_DETECTION_BLE_GATT_CLIENT_PROBE=y

# Optional: Custom Studio RPC + Web UI for live state and BLE overrides
CONFIG_ZMK_STUDIO=y
CONFIG_ZMK_OS_DETECTION_STUDIO_RPC=y
CONFIG_ZMK_CUSTOM_SETTINGS=y
CONFIG_ZMK_CUSTOM_SETTINGS_STUDIO_RPC=y
CONFIG_ZMK_STUDIO_RPC_RX_BUF_SIZE=128
CONFIG_ZMK_LOW_PRIORITY_THREAD_STACK_SIZE=2048
```

Full option list is in [Kconfig](./Kconfig).

## C API

```c
#include <cormoran/os-detection/os_detection.h>

enum zmk_os { ZMK_OS_UNKNOWN, ZMK_OS_WINDOWS, ZMK_OS_MACOS, ZMK_OS_LINUX };

enum zmk_os zmk_os_detection_current(void); // effective OS for the active endpoint

// Subscribe to zmk_os_changed via ZMK_LISTENER/ZMK_SUBSCRIPTION to react to changes.
```

## Web UI

See [web/README.md](./web/README.md) for local web development.

1. Connect Studio to your keyboard (Web Serial - Chrome/Edge only) at the
   published UI URL: https://cormoran.github.io/zmk-feature-os-detection/
2. The **USB** card shows whether USB is connected and the detected OS.
3. The **BLE Profiles** table lists every paired profile (bonded /
   connected / detected / override / effective), with the currently active
   profile highlighted. Use the dropdown in the **Override** column to pin
   a profile to Windows/macOS/Linux, or back to **AUTO**. The override is
   saved to the keyboard's persistent settings immediately and survives
   reboots.

**Publishing**: merging to `main` builds and deploys the Web UI to GitHub
Pages automatically (see `.github/workflows/web-ui.yml`).

## Known limitations

- **USB fingerprints are OS-version-dependent.** The `wLength` pattern a
  given Windows/macOS/Linux version requests can change between OS
  releases; treat the classifier as a best-effort guess, not a guarantee.
- **Any OS sharing the Linux kernel's USB host stack enumerates like
  Linux over USB and is reported as `ZMK_OS_LINUX`** — ChromeOS, and (real
  capture, 2026-07-05) Android in USB-host/OTG mode too, whose kernel-level
  enumeration was byte-for-byte identical to desktop Linux's. **USB alone
  also cannot reliably distinguish macOS from iOS** (both use Apple's USB
  HID stack). There's no separate Android/ChromeOS/iOS value in `enum
  zmk_os` - this is by design, not a gap to fill.
- **KVM switches and some USB hubs don't force re-enumeration** on switch,
  so USB detection can miss a host change until the next physical
  reconnect.
- **The USB hook requires Zephyr's legacy USB device stack**
  (`CONFIG_USB_DEVICE_STACK`). If ZMK ever migrates to the newer
  `device_next` stack, `--wrap=usb_handle_bos` stops applying and the
  build will fail loudly (a `CMakeLists.txt` check turns this into a clear
  error rather than a silently-broken feature) - the long-term fix is an
  observation hook contributed to ZMK itself
  ([zmkfirmware/zmk#2553](https://github.com/zmkfirmware/zmk/issues/2553)).
- **BLE detection is inherently heuristic.** Treat per-profile manual
  override via the Web UI as the primary way to get a reliable result;
  auto-detection is only a first guess, refined as more GATT signals
  arrive.
- **Custom Studio RPC is an unofficial protocol** and requires the
  `cormoran/zmk` fork (`main+custom-studio-protocol`) rather than upstream
  ZMK.
- **Split keyboards**: detection only runs on the central side, since only
  the central owns the USB/BLE host connection.
- USB detection is verified against real captures for all three target OSes
  (macOS, Windows, Linux — 2026-07-05). All of BLE is still an unverified
  placeholder - see [docs/fingerprints.md](docs/fingerprints.md) for exactly
  what was captured, what's still a guess, and how to update either with
  new real capture data (including a working J-Link RTT capture recipe).

## Development

### Setup

```bash
git clone https://github.com/cormoran/zmk-feature-os-detection
cd zmk-feature-os-detection
west init -l west --mf west-test-isolated.yml
west update --narrow
west zephyr-export
```

(Dev container users: this is done automatically.)

### Pre-commit

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

### Tests

```bash
# Unit tests (native_sim, incl. TEST_INJECT USB/RPC scenarios) + build tests
python3 -m unittest
# Build tests only
west zmk-build tests/zmk-config
# Unit tests only
west zmk-test tests -m .
# Web UI tests
cd web && npm test
```

### Manual real-hardware verification

Automated tests cover the classifier logic and RPC/build wiring, but the
actual fingerprint thresholds need verification against real hosts before
you can trust them:

1. Flash a board with `CONFIG_ZMK_OS_DETECTION_USB=y` (and `_BLE=y` if
   testing BLE) enabled.
2. **USB**: already verified against a real Mac, a real Windows PC, and a
   real Linux machine (see [docs/fingerprints.md](docs/fingerprints.md)).
   If you want to re-verify against a different OS version, plug into that
   host and capture the enumeration with `usbmon` (Linux: `sudo modprobe
   usbmon; sudo cat /sys/kernel/debug/usb/usbmon/1u`), Wireshark+USBPcap
   (Windows), or Wireshark's built-in USB capture (macOS) - or, if you have
   J-Link SWD access to the board (independent of whatever host its USB-C
   is plugged into), flash a debug build and read the module's own
   `zmk_os_detection_observe_setup()` `LOG_DBG` output straight out of
   target RAM; see [docs/fingerprints.md](docs/fingerprints.md)'s "RTT
   capture recipe" for the exact commands (this is how the existing
   signatures were captured). Compare against `zmk_os_detection_current()`
   / the Web UI's USB card, and update the thresholds in
   `src/os_detection_usb.c` + `docs/fingerprints.md` to match what you
   actually captured.
3. **BLE**: pair the same board with a Windows PC, a Mac, an iPhone, and a
   Linux desktop. Check the Web UI's BLE profile table for each; use
   `btmon` (Linux) or `PacketLogger` (macOS) to see the actual GATT access
   pattern if the auto-detected OS is wrong, and adjust
   `src/os_detection_ble.c` + `docs/fingerprints.md`.
4. Confirm overrides set from the Web UI persist across a reboot.

### Sync changes from template

Run `Actions > Sync Changes in Template > Run workflow` to pull in
upstream template changes as a pull request.

### Coding agent on actions

- Mention `@copilot`
- Setup `ANTHROPIC_API_KEY` secret and mention `@claude`
