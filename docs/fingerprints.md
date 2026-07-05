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
requests it too (see the real Linux capture further down: Linux does as
well, at the same minimal length — BOS-requested-or-not turned out not to
discriminate macOS from Linux at all once both were captured).
`zmk_os_classify_usb()` and `inject_macos_like()` in `src/os_detection_usb.c`
were updated to match this verified data — macOS is now recognized by the
short-probe-then-full-reread pattern on every descriptor, independent of
BOS.

### Real Windows capture (2026-07-05, verified)

**Method**: identical to the macOS capture above — same debug build, same
RTT-read recipe — except the board's USB-C was moved to a real Windows PC.

Raw sequence captured (repeated identically 3 times in a row in the
captured log, suggesting the host re-enumerated/retried multiple times;
shown once here):

```
GET_DESCRIPTOR(DEVICE)        wLength=64   (partial probe - not macOS's 8)
GET_DESCRIPTOR(DEVICE)        wLength=18   (full)
GET_DESCRIPTOR(CONFIGURATION) wLength=255  (straight to max length, no short header probe first)
GET_DESCRIPTOR(BOS)           wLength=255  (straight to max length, no short header probe first)
```

Notably: **no string descriptors were requested at all** (no manufacturer/
product/serial string reads), unlike macOS's three. Both configuration and
BOS were fetched directly at `wLength=255` with no short-probe-then-full
two-phase pattern — the opposite of macOS's behavior for those same
descriptors. Device descriptor was probed at `wLength=64` first (macOS used
8).

This confirmed the "Windows requests BOS at more than the minimal header
length" guess from the previous (pre-Windows-capture) revision of this
file was directionally correct, so `zmk_os_classify_usb()`'s Windows branch
(`bos_requested && bos_wlength > 5`) needed no logic change — only
`inject_windows_like()` in `src/os_detection_usb.c` was updated to replay
this real sequence instead of the old guessed one. The device-descriptor
probe length (64 vs macOS's 8) and the direct-to-255 configuration read are
recorded here as additional real, verified signals **not yet wired into the
classifier** (current logic only inspects string reads and BOS length) -
worth adding if the BOS-only signal ever proves too coarse against a wider
range of real Windows/macOS versions.

### Real Linux capture (2026-07-05, verified)

**Method**: identical recipe again, board's USB-C moved to a real Linux
machine.

Raw sequence captured, cold boot to just after `SET_CONFIGURATION`:

```
GET_DESCRIPTOR(DEVICE)                          wLength=64  (partial probe - same as Windows, not macOS's 8)
GET_DESCRIPTOR(DEVICE)                          wLength=18  (full)
GET_DESCRIPTOR(BOS)                             wLength=5   (minimal header, same as macOS - not a discriminating signal)
GET_DESCRIPTOR(DEVICE_QUALIFIER)                wLength=10  (repeated 3x identically - this device has no qualifier, so the kernel retries)
GET_DESCRIPTOR(CONFIGURATION)                   wLength=9   (header probe, same pattern as macOS)
GET_DESCRIPTOR(CONFIGURATION)                   wLength=34  (full)
GET_DESCRIPTOR(STRING, index=0)                 wLength=255 (the language-ID list itself, not just indexed strings)
GET_DESCRIPTOR(STRING, index=2, langid=0x0409)  wLength=255
GET_DESCRIPTOR(STRING, index=1, langid=0x0409)  wLength=255
GET_DESCRIPTOR(STRING, index=3, langid=0x0409)  wLength=255
SET_CONFIGURATION(1)
GET_DESCRIPTOR(STRING, index=3, langid=0x0409)  wLength=255 (re-read after SET_CONFIGURATION, likely the HID subsystem re-fetching the serial number)
GET_DESCRIPTOR(REPORT, interface recipient)     wLength=77  (HID class request, expected post-enumeration)
```

This is the capture that actually broke the classifier as it stood after
the Windows capture: the "macOS requests BOS at its minimal length"
signal (`bos_wlength <= 5`) is equally true of Linux, so BOS-requested
status doesn't discriminate the two at all — every real macOS *and* real
Linux capture so far has requested BOS once at exactly 5 bytes. Without a
Linux capture this collision was invisible; the previous revision's
`zmk_os_classify_usb()` would have misclassified this exact real trace as
macOS (falling through to the "BOS activity but no clear string pattern"
fallback branch, which returned macOS unconditionally).

Fixed by dropping the BOS check from both the macOS and Linux branches
entirely and discriminating purely on how *string* descriptors are read
(the only signal that actually differed): macOS does the short-probe-then-
full-reread two-phase pattern on every string, Linux reads every string
(including index 0, the language-ID list) directly at the full 255-byte
buffer with no header probe. The unconditional macOS fallback was removed
too — an unrecognized pattern now correctly returns `ZMK_OS_UNKNOWN` rather
than guessing macOS. `inject_linux_like()` was updated to replay this real
sequence. The `DEVICE_QUALIFIER`-retried-3-times behavior is a real,
distinctive Linux-only signal (neither macOS nor Windows requested it at
all) that isn't wired into the classifier yet — worth adding if the
string-pattern signal ever proves ambiguous.

**USB fingerprinting is now verified for all three target OSes** (macOS,
Windows, Linux). Remaining USB caveats are about generalization, not "no
data at all" - see "Known fragility" below.

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
gated at `LOG_DBG`) plus this recipe is what captured all three real traces
above.

### Still unverified

USB is now verified for all three target OSes. Only **BLE** remains
entirely unverified (see below) — and even for USB, treat "verified" as
"verified against one specific version of one specific OS on 2026-07-05",
not "guaranteed for every version forever". `CONFIG_ZMK_OS_DETECTION_TEST_INJECT`
lets any future threshold change be regression-tested with
`tests/os_detection_usb` alone, no hardware required for the
re-verification step, if a different OS version's real behavior turns out
to differ from what's captured here.

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
