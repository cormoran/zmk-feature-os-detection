# USB / BLE fingerprint data

This document records what real-hardware evidence backs the classifiers in
`zmk_os_classify_usb()` / `zmk_os_classify_ble()`, and is honest about which
thresholds are still **unverified placeholders**.

## USB

### What this environment can and cannot capture

This development sandbox does have a real, physical XIAO BLE + PMW3610 board
attached over USB (confirmed via `lsusb`: `1d50:615e "Module Test"`, the same
`CONFIG_ZMK_KEYBOARD_NAME` used by `tests/zmk-config`) and a SEGGER J-Link for
flashing it over SWD — see `skills/develop-zmk-module/references/hardware-rig.md`
in the parent workspace. So, in principle, this sandbox *is* a real Linux USB
host for the board.

In practice, packet-level SETUP capture was not possible here:

- `usbmon` (the kernel facility `usb_handle_bos`-style captures normally rely
  on, via `/sys/kernel/debug/usb/usbmon`) is not available: `modprobe usbmon`
  fails with "Module usbmon not found" — the container's kernel
  (`5.15.0-185-generic`) does not ship it, and modules can't be added to a
  shared/virtualized container kernel.
- `/sys/kernel/debug` is present but access to `usb/usbmon` under it is
  denied even as root inside the container.
- `dmesg` is also restricted (`Operation not permitted` for the raw ring
  buffer) and, when accessible via `sudo dmesg`, only showed unrelated BLE
  `uhid` virtual-device churn from a previous BLE pairing, no USB control
  transfer detail.

So **no real wLength/BOS enumeration sequence could be captured for any OS in
this environment**, including Linux, despite having the real board attached.
This is a harder constraint than "no Windows/macOS machine" — it's "no
packet-capture capability for USB at all," on any host.

### Placeholder classifier thresholds (UNVERIFIED — replace before shipping)

`zmk_os_classify_usb()` uses these buckets purely from the task brief's
stated general tendencies, not from captured data:

| Signal                                             | Windows (guess) | macOS (guess)     | Linux (guess) |
| --------------------------------------------------- | --------------- | ------------------ | ------------- |
| `GET_DESCRIPTOR(String)` requested with `wLength=255` | rare/never      | sometimes          | once, reliably |
| Same string re-requested at multiple `wLength`s      | yes             | sometimes          | no            |
| `GET_DESCRIPTOR(BOS)` requested                      | yes             | inconsistent       | inconsistent  |

**Anyone deploying this module for real should capture their own data**
(e.g. on a machine where `usbmon` works: `sudo modprobe usbmon; sudo cat
/sys/kernel/debug/usb/usbmon/1u`, or Wireshark + USBPcap on Windows, or
`Wireshark` + the built-in USB capture on macOS) for each target OS and
replace the bucket thresholds in `os_detection_usb.c` / this table. The
`ZMK_OS_DETECTION_TEST_INJECT` mechanism in `tests/test/` exists so replacing
these thresholds can be verified by unit test alone, without new hardware —
see `tests/test/README` for how to add a new recorded sequence.

Known fragility (see README "Known limitations" for the full list): the
wLength pattern is OS-version-dependent, ChromeOS enumerates like Linux, and
USB alone cannot distinguish macOS from iOS.

## BLE

Same situation as USB: this sandbox has no Bluetooth host controller exposed
to it for pairing/testing against a real Windows/macOS/Linux/iOS BLE stack
(`bluetoothctl`/`hcitool` show no local adapter), so the GATT-read-order,
MTU, and connection-parameter thresholds in `zmk_os_classify_ble()` are, like
USB, placeholders taken from the general behavior described in the task
brief and from public documentation of each OS's BLE HID stack, not from a
capture on this specific board. `CONFIG_ZMK_OS_DETECTION_BLE_GATT_CLIENT_PROBE`
(ANCS/AMS detection) is Apple-specific and considered higher-confidence than
the timing-based heuristics once implemented, but still needs real-device
verification.

**Action item for a human with the real hardware**: pair the board with a
Windows PC, a Mac, an iPhone, and a Linux desktop, capture GATT logs (e.g.
`btmon` on Linux, `PacketLogger` on macOS, or firmware-side `LOG_INF` of
`struct ble_fp_stats` before classification — the module logs this at `DBG`
level), and update the thresholds in `os_detection_ble.c`.
