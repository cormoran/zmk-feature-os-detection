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

**USB fingerprinting is now verified for macOS, Windows, and Linux**
(iOS follows further down, once it turned out to actually differ from
macOS). Remaining USB caveats are about generalization, not "no data at
all" - see "Known fragility" below.

### Real Android capture (2026-07-05) — confirms the documented Linux/Android ambiguity

**Method**: identical recipe again, board's USB-C moved to a real Android
device (acting as USB host, i.e. OTG).

The kernel-level enumeration sequence was **byte-for-byte identical** to
the real Linux capture above: `DEVICE(64, 18)` → `BOS(5)` →
`DEVICE_QUALIFIER(10)` ×3 → `CONFIGURATION(9, 34)` → `STRING(index 0, 2,
1, 3)` all at `wLength=255` → `SET_CONFIGURATION`. Unsurprising — Android's
USB host-mode stack is the same Linux kernel USB core as desktop Linux.
`zmk_os_classify_usb()` therefore reports `ZMK_OS_LINUX` for this Android
device too, which is *correct given this module's design*: there is no
separate `ZMK_OS_ANDROID` value in `enum zmk_os` (see the task's own "Known
limitations" - USB alone can't distinguish OSes sharing a kernel, ChromeOS
was already called out as the same case), so "reads like Linux" reporting
`ZMK_OS_LINUX` is the intended, documented outcome, not a bug.

One difference from the Linux capture, after `SET_CONFIGURATION` and the
HID `REPORT` descriptor read: Android's capture showed *additional*
trailing string-descriptor re-reads (index 0 again, at `wLength=254` this
time - one byte less than every other request in either capture, cause
unknown) that the desktop Linux capture didn't have. Plausibly Android's
userspace input/HID service doing its own extra descriptor pass on top of
the kernel's enumeration, distinct from vanilla desktop Linux's udev-driven
flow. Not classification-relevant (happens after `SET_CONFIGURATION`, well
past the debounce window that already settled on `ZMK_OS_LINUX`), but
recorded here in case a future capture shows it's actually a stable,
distinguishing signal worth acting on.

### Real iPhone (iOS) capture (2026-07-05, verified) — iOS split out from macOS

**Method**: identical recipe again, board's USB-C moved to a real iPhone.

Raw sequence captured, cold boot through the post-enumeration HID `REPORT`
descriptor read:

```
GET_DESCRIPTOR(DEVICE)                          wLength=8   (partial probe - same as macOS, not Android/Linux/Windows's 64)
GET_DESCRIPTOR(DEVICE)                          wLength=18  (full)
GET_DESCRIPTOR(STRING, index=2, langid=0x0409)  wLength=2   (header probe)
GET_DESCRIPTOR(STRING, index=2, langid=0x0409)  wLength=24  (full)
GET_DESCRIPTOR(STRING, index=1, langid=0x0409)  wLength=2   (header probe)
GET_DESCRIPTOR(STRING, index=1, langid=0x0409)  wLength=24  (full)
GET_DESCRIPTOR(STRING, index=3, langid=0x0409)  wLength=2   (header probe)
GET_DESCRIPTOR(STRING, index=3, langid=0x0409)  wLength=34  (full)
GET_DESCRIPTOR(CONFIGURATION)                   wLength=9   (header probe)
GET_DESCRIPTOR(CONFIGURATION)                   wLength=34  (full)
GET_DESCRIPTOR(BOS)                             wLength=5   (minimal header, same as macOS)
SET_CONFIGURATION(1)
SET_FEATURE(DEVICE_REMOTE_WAKEUP)               ← not seen in the real macOS capture
GET_DESCRIPTOR(REPORT, interface recipient)     wLength=77  (HID class request, expected post-enumeration)
```

Through `BOS`, this is **identical** to the real macOS capture (device
probed at `wLength=8`, same short-probe-then-full-reread pattern on every
string and on configuration, minimal 5-byte BOS read) — consistent with
both sharing Apple's USB stack heritage. The one real, reproducible
difference: right after `SET_CONFIGURATION`, the iPhone sent
`SET_FEATURE(DEVICE_REMOTE_WAKEUP)` (`bRequest=0x03`,
`wValue=0x0001`/`USB_SFS_REMOTE_WAKEUP`, device recipient) — a real macOS
host did not do this in its capture.

Per the task's request: since there **is** a real, observed difference,
`ZMK_OS_IOS` was added as its own value (`= 4`, appended after
`ZMK_OS_LINUX` to keep existing values' numbers stable; proto `OS_IOS = 5`
for the same reason) rather than continuing to fold iOS into
`ZMK_OS_MACOS`. `usb_fp_stats` gained a `remote_wakeup_enabled` bool, set
when `zmk_os_detection_observe_setup()` sees
`SET_FEATURE(DEVICE_REMOTE_WAKEUP)`; `zmk_os_classify_usb()`'s macOS/iOS
branch now returns `ZMK_OS_IOS` when that bool is set and `ZMK_OS_MACOS`
otherwise, everything else about the branch (the short-probe-then-full
string/config pattern, minimal BOS) staying exactly as the macOS capture
established it. `inject_ios_like()` replays this real sequence;
`inject_macos_like()` is unchanged and correctly has
`remote_wakeup_enabled` stay false.

This split also touches `os_detection_ble.c`: the ANCS/AMS opt-in GATT
client signal (`ZMK_OS_DETECTION_BLE_GATT_CLIENT_PROBE`) was previously
mapped to `ZMK_OS_MACOS`, but ANCS/AMS are services an iPhone/iPad exposes
to accessories, not something macOS exposes as a BLE peripheral - that
branch now correctly returns `ZMK_OS_IOS`. This is still an unverified BLE
placeholder either way (no real BLE capture exists yet), just a more
technically accurate one.

**Caveat**: this is one data point. `SET_FEATURE(DEVICE_REMOTE_WAKEUP)`
being iOS-specific-and-always-present is not something that's been checked
against multiple iOS versions or multiple real Mac sessions run long
enough to be sure macOS categorically never sends it later in a session
(the real macOS capture simply wasn't watched past `SET_CONFIGURATION`).
Treat `ZMK_OS_IOS` as verified-but-narrow, same caution as every other
branch in this file.

### RTT capture recipe (for the next real-hardware session)

See [hw-capture-recipe.md](hw-capture-recipe.md) for the exact,
copy-pasteable commands (flash-offset overlay content, build command,
JLinkExe scripts) - this section is the short prose version.

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
gated at `LOG_DBG`) plus this recipe is what captured all real traces
above (macOS, Windows, Linux, Android, iOS).

### Still unverified

USB is now verified for macOS, Windows, Linux, Android (as Linux), and iOS.
Only **BLE** remains entirely unverified (see below) — and even for USB,
treat "verified" as "verified against one specific version of one specific
OS on 2026-07-05", not "guaranteed for every version forever".
`CONFIG_ZMK_OS_DETECTION_TEST_INJECT` lets any future threshold change be
regression-tested with `tests/os_detection_usb` alone, no hardware required
for the re-verification step, if a different OS version's real behavior
turns out to differ from what's captured here.

Known fragility (see README "Known limitations" for the full list): the
wLength pattern is OS-version-dependent. USB alone still cannot distinguish
ChromeOS from Linux (both share the kernel), but macOS and iOS **are** now
distinguished (see the iPhone capture above) — narrower than the original
task brief assumed, on one signal only.

## BLE

Like USB, this sandbox itself has no Bluetooth host controller usable for
pairing (`hciconfig -a` fails with "Address family not supported by
protocol" - no `AF_BLUETOOTH` at all). But the same trick that unblocked USB
works here too: the physical XIAO board can actually be paired over BLE with
a real host while J-Link SWD/RTT logging keeps working from this sandbox
(electrically independent radios). `os_detection_ble.c` was extended with
per-event `LOG_DBG` lines (every GATT read, MTU update, connection
parameter update, and the live `ble_fp_stats` before each classification -
mirroring what `os_detection_usb.c` already did for SETUP packets) to make
this capturable. See `docs/hw-capture-recipe.md` for the exact commands;
the BLE-specific differences from the USB recipe are `CONFIG_ZMK_BLE=y`
(don't disable it - it's what's being tested this time) and a much bigger
`CONFIG_SEGGER_RTT_BUFFER_SIZE_UP` (65536, not 8192) since BLE connection
churn is far chattier than a single USB enumeration.

**Sandbox-specific gotcha that cost significant time**: this rig's Linux
host itself has a Bluetooth controller (`5C:87:9C:0B:32:DF`) with its own
stale bond to the board from unrelated earlier testing (`EA:7D:49:6E:DE:B4`,
"Module Test"), which auto-reconnects and fails authentication in a tight
loop, consuming the RTT buffer and confusing capture attempts. Access this
host's BlueZ via `DBUS_SYSTEM_BUS_ADDRESS=unix:path=/mnt/host-dbus/system_bus_socket
bluetoothctl` (path may vary - was `/run/host-dbus/...` before, changed to
`/mnt/host-dbus/...`; a bare `bluetoothctl` hangs at "Waiting to connect to
bluetoothd" without this), `select 5C:87:9C:0B:32:DF`, then `paired-devices`
+ `remove <addr>` to clear it. Also: **`JLinkExe`'s `loadbin` does *not*
erase flash before writing** - writing all-`0xFF` over a NOR flash sector
that already holds real data is a silent no-op (flash can only clear bits
1→0 without an erase cycle), so the `storage_partition`-wipe trick used for
USB captures (§1 of `hw-capture-recipe.md`) never actually worked for BLE
bond data. Verify erasure with a direct `mem32` read after erasing, and use
`erase <start>, <end>` (a *ranged* sector erase, not the blanket full-chip
`erase`) instead of `loadbin` when the goal is to actually clear a region:
```
JLinkExe ... -CommandFile <(echo -e "erase 0xD4000, 0xF4000\nmem32 0xD4000, 0x10\nexit")
```

### Real macOS capture (2026-07-05, verified, partial)

A real Mac connected (`bt_smp` security level 2 - encrypted, unauthenticated)
and, in the observed window, only explored the Device Information Service:
`2a29` (Manufacturer Name), `2a24` (Model Number), `2a50` (DIS PnP ID, twice)
- no HIDS (Report Map/Info) access happened before the connection went idle.
ATT MTU was 65, connection interval 24 (30ms), later renegotiated to 12
(15ms)/latency 0/timeout 72 (720ms). `zmk_os_classify_ble()` classified this
as `ZMK_OS_MACOS`, but only via the **fallback** branch (no report_map,
hids_info, or appearance seen) - i.e. this data point doesn't yet exercise a
macOS-*specific* rule, it just doesn't match the Windows or Linux rules
either. Treat "macOS classifies correctly" as true-so-far but weakly
verified until a capture shows it actually reading HIDS.

### Real Windows capture (2026-07-05, verified)

A real Windows PC connected, reached security level 2, and did a much more
thorough GATT walkthrough than macOS: HIDS Report (`2a4d`), HIDS Report Map
(`2a4b`), HIDS Info (`2a4a`), DIS PnP ID (`2a50`), Manufacturer Name/Model
Number, Battery Level, GAP Appearance (`2a01`), GAP Device Name, plus several
generic descriptor/declaration reads (`2803`, `2902`, `2908`, `2904`) not
tracked as signals. Connection interval started at 15 (18.75ms), later
renegotiated to 12 (15ms)/timeout 200 (2s).

This is the first BLE data point that exercises the Windows-*specific* rule
(`pnp_id > 0 && appearance > 0`) rather than falling back, and it correctly
settled on `ZMK_OS_WINDOWS` - a real, if narrow, validation of the existing
placeholder logic.

**Real bug this capture exposed**: `zmk_os_classify_ble()` is called and its
result reported live after *every single* GATT read (no debounce, unlike
USB's `usb_settle_work` delay), so the reported OS visibly changes as more
characteristics get read within one connection. This capture's actual
sequence of *reported* values was UNKNOWN → `ZMK_OS_MACOS` (fallback, once
only report_map was seen) → **`ZMK_OS_LINUX`** (once hids_info arrived too,
satisfying the Linux rule `report_map>0 && hids_info>0 && pnp_id==0`) →
`ZMK_OS_MACOS` again (once pnp_id arrived, breaking the Linux match) →
finally `ZMK_OS_WINDOWS` (once appearance arrived too) - four different
classifications inside about 1.8 seconds for what is actually one Windows
host. Anything reading `zmk_os_detection_current()` or the `zmk_os_changed`
event mid-connection (e.g. an auto-layer-switch) could act on the wrong,
transient value. **Not fixed yet** - worth a debounce similar to USB's
before relying on the auto-layer-switch feature over BLE.

### Real Linux capture (2026-07-05, verified) — found Windows/Linux are NOT distinguishable this way

Paired directly from this sandbox's own host machine (real BlueZ, driven via
`bluetoothctl` over the host D-Bus socket - see the sandbox-note above) to
rule out any doubt about it being a "real enough" Linux BLE stack. The
resulting GATT read pattern: `report_map=2 hids_info=1 report_ref=2
pnp_id=2 appearance=1` - **structurally identical** to the real Windows
capture above (`report_map=2 hids_info=1 report_ref=2 pnp_id=1
appearance=1`), same set of characteristics touched, only counts differ
(not a meaningful signal). MTU was 0 in both captures - `att_mtu` isn't
reliably populated yet, a separate gap worth investigating.

This means PnP ID presence/absence, the *original* assumed Windows/Linux
split, **cannot actually distinguish real Windows from real Linux/BlueZ** -
both read it. The only difference spotted between these two specific
captures was connection parameters (Windows: interval 12, timeout 200;
Linux: interval 12, **latency 30**, timeout 400) - a single sample each,
not trustworthy as a real discriminator on its own.

**Decision (2026-07-05, per module owner)**: given this ambiguity is real
and not just a missing threshold, and Windows has the larger install base
among likely users of this module, `zmk_os_classify_ble()` deliberately
checks the Windows rule before the Linux rule so this specific ambiguous
GATT pattern (PnP ID + Appearance both present) resolves to `ZMK_OS_WINDOWS`.
See the real Android capture below for how the Linux branch's actual
condition was later corrected from "no PnP ID" (wrong) to "no Appearance"
(right) - this decision still holds with that fix in place, since this
Linux desktop capture read Appearance too and still lands on the Windows
rule above, unchanged.

### Real iPhone capture (2026-07-05, verified) — confirms iOS is NOT distinguished from macOS over BLE yet

A real iPhone connected using a **random** address (`4D:FD:77:9F:F9:75
(random)`) - notably different from every other real capture so far
(macOS/Windows/Linux all connected with a **public** address). Read only
`2a4b` (HIDS Report Map, twice) plus untracked characteristics (Device
Name, a Report Reference descriptor, one generic declaration, Battery
Level) - **no** DIS PnP ID, no GAP Appearance, no HIDS Info were read at
all. Connection interval 12 (15ms), latency 4, timeout 100 (1s).

With `report_map>0` and everything else zero, this doesn't match the
Windows or Linux rules and falls to the fallback branch, same as the
earlier partial macOS capture - `zmk_os_classify_ble()` reports
`ZMK_OS_MACOS`, not `ZMK_OS_IOS`. This confirms what was predicted before
capturing: `CONFIG_ZMK_OS_DETECTION_BLE_GATT_CLIENT_PROBE` (the ANCS/AMS
signal meant to distinguish iOS) is a Kconfig-only stub - it selects
`BT_GATT_CLIENT` but no code anywhere performs the actual ANCS/AMS
discovery/read, so `ble_fp_stats.ancs_or_ams_present` is never set `true`
by anything, and **iOS and macOS are indistinguishable in this module's
BLE detection today** (they share the exact same fallback outcome).

**Decision (2026-07-05, per module owner)**: same reasoning as the
Windows/Linux ambiguity above - since this fallback case genuinely can't
tell iOS and macOS apart today, and it already unconditionally returns
`ZMK_OS_MACOS`, that's kept as the deliberate default (no code change was
needed - the existing fallback already resolves this exact way).

**Unverified lead worth following up**: the random-vs-public address type
difference (iPhone: random: every other real capture: public) is
consistent across the one sample each collected here and matches Apple's
documented general preference for BLE address privacy on iOS, but
`ble_fp_stats` doesn't currently record address type at all - this isn't
implemented or acted on, just noted as a promising direction if iOS/macOS
disambiguation is worth pursuing later (needs more than one sample per OS
before trusting it).

### Real Android capture (2026-07-05, verified) — Android IS distinguishable from Linux over BLE, unlike over USB

A real Android device connected using a **random** address
(`53:C8:54:41:01:33 (random)`) - same as the iPhone capture, unlike the
public addresses macOS/Windows/desktop-Linux all used. It did a much more
thorough service walk than any other capture (over a dozen generic `2803`
characteristic-declaration reads), then read: DIS PnP ID (`2a50`), HIDS
Info (`2a4a`), HIDS Report Map (`2a4b`, four times), plus untracked
characteristics (Database Hash, Battery Level, Peripheral Preferred
Connection Parameters). **GAP Appearance was never read.** Connection
interval settled at 12 (15ms), latency 30, timeout 400 (4s) - notably the
*same* latency/timeout as the real Linux desktop capture above, unlike
Windows's (latency 0, timeout 200).

With `report_map>0`, `hids_info>0`, `pnp_id>0`, and `appearance==0`, this
doesn't match the Windows rule (needs `appearance>0`) - so unlike the
desktop Linux capture (which does read Appearance and lands on Windows),
**Android's absence of an Appearance read is a real, working signal that
separates it from both Windows and desktop Linux.**

This exposed two real, evidence-based fixes:

1. **The Linux rule's condition was wrong.** It originally checked
   `pnp_id_reads == 0`, based on the pre-real-data assumption that Linux
   skips DIS entirely. Real data across Windows/desktop-Linux/Android shows
   that assumption never held - all three read PnP ID. The rule was
   corrected to check `appearance_reads == 0` instead, which is what
   actually separates Android from Windows/desktop-Linux in every real
   capture collected so far.
2. **Android now gets its own `ZMK_OS_ANDROID` value over BLE** (per module
   owner, 2026-07-05), unlike over USB where it's deliberately folded into
   `ZMK_OS_LINUX` (kernel-level USB enumeration is identical there - see
   the USB section above). The BLE GATT read pattern is NOT identical
   between Android and desktop Linux (this capture proves it), so folding
   them together over BLE would throw away a real, working signal for no
   reason. `zmk_os_classify_ble()`'s corrected Linux-shaped rule
   (`report_map>0 && hids_info>0 && appearance==0`) now returns
   `ZMK_OS_ANDROID` instead of `ZMK_OS_LINUX`.

One consequence worth being explicit about: with only Windows, desktop
Linux, and Android real captures backing this logic, `zmk_os_classify_ble()`
currently has **no path that returns `ZMK_OS_LINUX` at all** - a real
desktop Linux connection (which reads Appearance) lands on the Windows
rule instead, per the existing Windows/Linux ambiguity decision above. If
a future real capture from a Linux desktop that genuinely skips Appearance
ever turns up, it would be misclassified as Android by the current logic
- something to watch for, not yet observed.
