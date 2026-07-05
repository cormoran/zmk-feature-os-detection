# USB / BLE fingerprint data

This document records what real-hardware evidence backs the classifiers in
`zmk_os_classify_usb()` / `zmk_os_classify_ble()`, and is honest about which
thresholds are still **unverified placeholders**.

## USB

### What this environment can and cannot capture

This development sandbox has a real, physical XIAO BLE + PMW3610 board and a
SEGGER J-Link for flashing/debugging it over SWD — see
`skills/develop-zmk-module/references/hardware-rig.md` in the parent
workspace. The board's own USB-C port (its "USB device" role, what actually
gets fingerprinted) and the J-Link's SWD connection are electrically
independent, so the board's USB-C can be plugged into *any* host OS while
J-Link SWD debugging/logging keeps working from this sandbox regardless.
Initially the board's USB-C was plugged into this sandbox itself (making it
a real Linux USB host for the board); it was later moved to a real Mac,
which is what made the "Real macOS capture" below possible.

In practice, kernel-level packet capture was not possible here:

- `usbmon` (the kernel facility `usb_handle_bos`-style captures normally rely
  on, via `/sys/kernel/debug/usb/usbmon`) is not available: `modprobe usbmon`
  fails with "Module usbmon not found" — the container's kernel
  (`5.15.0-185-generic`) does not ship it, and modules can't be added to a
  shared/virtualized container kernel.
- `/sys/kernel/debug` is present but access to `usb/usbmon` under it is
  denied even as root inside the container.
- `dmesg` is also restricted (`Operation not permitted` for the raw ring
  buffer).

This is a constraint on capturing from the **host** side. It doesn't block
capturing from the **device** side, which is what this module actually
needs anyway (it observes SETUP packets from inside the keyboard's own
firmware, not from the host's kernel). See "Real macOS capture" below for
how that was done once a real Mac was available to plug the board into.

### Real macOS capture (2026-07-05, verified)

**Method**: with the physical XIAO board's USB-C connected to a real Mac
(instead of this sandbox), and its SWD pins still attached to this
sandbox's J-Link, a debug build was flashed with `CONFIG_ZMK_LOG_LEVEL_DBG=y`
+ `CONFIG_LOG_BACKEND_RTT=y` and a `LOG_DBG` line logging every raw SETUP
packet in `zmk_os_detection_observe_setup()` (still present in the code,
gated at `DBG` level — harmless in normal builds). RTT logs were then read
directly out of target RAM with `JLinkExe`'s `mem32`/`savebin`, without ever
running `JLinkRTTLogger`/`JLinkRTTClient` successfully (see "RTT capture
recipe" below for why and how). This confirms the technique in the README's
"Manual real-hardware verification" section works end-to-end.

Raw sequence captured from cold boot to `SET_CONFIGURATION` (host = a real
Mac; exact macOS version unknown to the firmware):

```
GET_DESCRIPTOR(DEVICE)                       wLength=8    (partial: probe bMaxPacketSize0)
GET_DESCRIPTOR(DEVICE)                       wLength=18   (full)
GET_DESCRIPTOR(STRING, index=2, langid=0x0409) wLength=2  (header probe)
GET_DESCRIPTOR(STRING, index=2, langid=0x0409) wLength=24 (full)
GET_DESCRIPTOR(STRING, index=1, langid=0x0409) wLength=2  (header probe)
GET_DESCRIPTOR(STRING, index=1, langid=0x0409) wLength=24 (full)
GET_DESCRIPTOR(STRING, index=3, langid=0x0409) wLength=2  (header probe)
GET_DESCRIPTOR(STRING, index=3, langid=0x0409) wLength=34 (full)
GET_DESCRIPTOR(CONFIGURATION, index=0)         wLength=9  (header probe, standard config desc size)
GET_DESCRIPTOR(CONFIGURATION, index=0)         wLength=34 (full, wTotalLength)
GET_DESCRIPTOR(BOS, index=0)                   wLength=5  (exactly sizeof(struct usb_bos_descriptor); never re-requested larger)
SET_CONFIGURATION(1)
```

Whole sequence completed in ~36ms (00:00:00.471 to 00:00:00.507 after boot).
No `wLength=255` request appeared anywhere. Every multi-byte descriptor
(device, each string, configuration) was read with the same **short 2-byte
header probe, then a second request at the full length** pattern. BOS was
requested exactly once, at its minimal 5-byte header size, with no follow-up
— this device's BOS has no extra capability descriptors, so there was
nothing more for the host to fetch; a device that advertises capabilities
might see a second, longer BOS read even from macOS.

This directly disproved part of the original placeholder heuristic: BOS
being requested was assumed to be a Windows-only signal, but real macOS
requests it too. `zmk_os_classify_usb()` and `inject_macos_like()` in
`src/os_detection_usb.c` were updated to match this verified data — macOS is
now recognized by short-probe-then-full-reread on strings **and** a
minimal-length-only BOS read (`bos_wlength <= 5`), with Windows tentatively
distinguished by requesting BOS at more than the minimal length (still an
unverified guess, since no real Windows capture exists yet).

### RTT capture recipe (for the next real-hardware session)

`JLinkRTTLogger`/`JLinkRTTClient` could not be made to find the RTT control
block in this environment, even pointed at the exact right address (from
`arm-zephyr-eabi-nm zmk.elf | grep _SEGGER_RTT`) — it always reported "RTT
Control Block not found". Worked around by reading RTT directly with
`JLinkExe`:

1. `mem32 <_SEGGER_RTT addr>, 0x8` to read the up-buffer-0 descriptor
   (`sName`, `pBuffer`, `SizeOfBuffer`, `WrOff`, `RdOff`).
2. **Important**: nRF52's `AIRCR.SYSRESETREQ` (what `JLinkExe`'s `r`/reset
   does) does not clear RAM. SEGGER's RTT init checks for its own "SEGGER
   RTT" signature already being present and, if found, skips
   re-initializing `WrOff`/`RdOff`/`pBuffer`/`sName` — so after reflashing a
   *different* build, the control block can keep pointing at stale metadata
   (e.g. a `sName` string address from the *previous* image) and never
   advance, even though the new firmware is running fine and actively
   producing log output elsewhere. Symptom: `WrOff`/`RdOff` frozen across
   multiple reset+wait cycles no matter how long you wait.
3. Fix: before each reset, zero out the first 16 bytes at the `_SEGGER_RTT`
   address (`w4 <addr>, 0x00000000` four times) to blank the signature, so
   the next boot's `SEGGER_RTT_Init()` treats it as uninitialized and does a
   real reset. Then `r` + `g`, wait, and `savebin <file> <pBuffer>
   <SizeOfBuffer>` to dump the up-buffer; `strings` on the result gives the
   log text (interleaved with ANSI color codes if
   `CONFIG_LOG_BACKEND_SHOW_COLOR=y` — harmless noise for `strings`/`grep`).
4. `CONFIG_LOG_PROCESS_THREAD_STARTUP_DELAY_MS` defaults to 5000 (5s) in a
   normal ZMK build — the deferred log backend won't flush anything before
   then. Override to `0` for hardware debug builds so logs appear
   immediately (as in `west build ... -DCONFIG_LOG_PROCESS_THREAD_STARTUP_DELAY_MS=0`).
5. Size `CONFIG_SEGGER_RTT_BUFFER_SIZE_UP` generously (8192 used here) if
   capturing anything beyond a couple dozen lines — `CONFIG_LOG_MODE_OVERFLOW`
   silently drops/overwrites old lines once full, and `DBG`-level ZMK boot
   logging is chatty (kscan pin config, behavior init, etc. all log before
   the interesting USB lines).

This module's own debug log line for every SETUP packet (`os_detection_usb.c`,
gated at `LOG_DBG`) plus this recipe is the fastest way to capture real
Windows/Linux data too — plug the board into that OS's real host, connect
J-Link's SWD pins to any Linux machine (SWD is independent of the target's
own USB connection), and repeat.

### Still unverified

Windows and Linux still have no real capture — the heuristics in
`zmk_os_classify_usb()` for those two remain placeholders per the original
task brief's stated tendencies, now reframed to not collide with the
verified macOS signature above. **Replace them the same way once real
Windows/Linux hardware is available**: `CONFIG_ZMK_OS_DETECTION_TEST_INJECT`
lets any updated thresholds be regression-tested with `tests/os_detection_usb`
alone, no hardware required for the re-verification step.

Known fragility (see README "Known limitations" for the full list): the
wLength pattern is OS-version-dependent, ChromeOS enumerates like Linux, and
USB alone cannot distinguish macOS from iOS.

## BLE

Same situation as USB: this sandbox has no Bluetooth host controller exposed
to it for pairing/testing against a real Windows/macOS/Linux/iOS BLE stack -
confirmed with `hciconfig -a`, which fails with "Can't open HCI socket:
Address family not supported by protocol" (`AF_BLUETOOTH` isn't available in
this container at all, not just "no adapter plugged in"). So the GATT-read-order,
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
