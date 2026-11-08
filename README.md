# Fork: Nothing Phone (3a) (`asteroids`)

This fork adds a `6.1.172-android14-11-g4538f521463f-ab16467005` profile for the
Nothing Phone (3a). Everything else is upstream. See
[Supported devices](#61172-4k--nothing-phone-3a).

---

# BIG NOTE: wait for 2-3 minutes after you logged into your device first time since new boot.
the device needs to stablize itself, background process may eat up ram, swap and cpu ( which is critical for this exploit).
## SMALL NOTE: To run root automatically, install shizuku-next, and manually run root once.
# TimerRoot

Android front end for **CVE-2026-98260** (POSIX CPU timer use-after-free), the
same class of bug as CVE-2026-64560. One tap gives you a root shell and then
late-loads **KernelSU** (`u:r:ksu:s0`).

The exploit itself is *not* included here. This repository is the app shell
around it: UI, state detection and the Shizuku plumbing needed to run a
shell-domain exploit from an ordinary app.

## Why the app needs Shizuku

An app runs as `untrusted_app` and cannot read `/sys/kernel/tracing`, which the
exploit needs for its leak and trigger. TimerRoot therefore starts a **Shizuku
user service**, which Shizuku runs as the shell user (`uid 2000`,
`u:r:shell:s0`). The exploit binary executes inside that process, so it gets
the same environment it would have from `adb shell`.

```
MainActivity (untrusted_app)
  └─ Shizuku user service (uid 2000, u:r:shell:s0)
       ├─ extracts assets/timer to /data/local/tmp/timer
       └─ runs it; on success keeps /system/bin/sh alive
```

## Requirements

- Android 12+ (`minSdk 30`), arm64
- [Shizuku](https://shizuku.rikka.app/) running (start it from the Shizuku app
  via wireless debugging, or over ADB)
- For unattended boots: one **Install channel** while a root shell is open, then
  one *Always allow* tap for TimerRoot's ADB key. After that the exploit runs on
  its own at every boot, before the first unlock (see
  [Auto-root on boot](#auto-root-on-boot))
- One supported manager installed, for the `Load KernelSU` path:
  [KernelSU](https://github.com/tiann/KernelSU),
  [KernelSU-Next](https://github.com/rifsxd/KernelSU-Next), or
  [SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)
- A device running one of the kernels this port covers (see
  [Supported devices](#supported-devices)):
  `6.1.162-android14-11-g9dd05ae3a1de-ab16261587` (Pixel 6 through Pixel 10a)
  or `6.6.127-android15-8-g91d825611104-ab16252310-4k` (Pixel 10 series). The
  upstream binary targets `6.12.69-android16-6-g242e1a07f878-ab15865446-4k`
  and will not work here.

## Getting the exploit binary

The exploit is build-specific: the timer call site, `cred` layout and
`task_struct` offsets differ per kernel, and a binary built for another build
will corrupt the kernel instead of failing safely. One binary carries a profile
for each kernel family this port covers: `6.1.162-android14-11-...` in the
`CP3A.261005.002.A1` and `CP3A.261005.005` builds (Pixel 6 through Pixel 10a)
and `6.6.127-android15-8-...-4k` in the Pixel 10 series' `CP3A.261005.005`
build. The profile is selected at startup from the running kernel banner and
userspace page size. See [Supported devices](#supported-devices).

The binary is not committed (`assets/timer` is gitignored). Build it and drop it
in place, or use **Download exploit**, which fetches the release asset and
installs it directly:

```
installed 2106912 bytes (uid=2000)
target=asteroids
kernel=6.1.162-android14-11-g9dd05ae3a1de-ab16261587
profile=4k
timer_site=0xffffffc0081932fc
```

On a Pixel 10 the same `target=asteroids` check passes and the kernel line reports
`6.6.127-android15-8-g91d825611104-ab16252310-4k` with profile `6.6-4k`.

After installing, the app always runs `timer target` and refuses any binary
whose `target=` line does not match `target=asteroids`.

The port derives every constant from the factory `boot.img` of that build
(kallsyms + BTF), so re-derive them before using it on a different kernel.

The binary is MIT licensed by its authors; only use it on hardware you own, and
only when your kernel matches the build it was ported to.

## Supported devices

The exploit is tied to a kernel build, not to a device name. One binary carries
a profile for each kernel family below and selects it at startup from the
running kernel banner and the userspace page size.

### 6.1.162 (4K and 16K)

`6.1.162-android14-11-g9dd05ae3a1de-ab16261587`, the GKI kernel shipped in the
`CP3A.261005.002.A1` and `CP3A.261005.005` factory images. Every device in this
table ships that exact kernel payload.

**Only the Pixel 7a and Pixel 9a have actually been run on hardware.**
Everything else in this table ships the same kernel and is expected to work,
but has not been run, so treat it as untested.

| Device | Codename | Factory build | Status |
|---|---|---|---|
| Pixel 6 | `oriole` | `CP3A.261005.002.A1` | untested |
| Pixel 6 Pro | `raven` | `CP3A.261005.002.A1` | untested |
| Pixel 6a | `bluejay` | `CP3A.261005.002.A1` | untested |
| Pixel 7 | `panther` | `CP3A.261005.002.A1` | untested |
| Pixel 7 Pro | `cheetah` | `CP3A.261005.002.A1` | untested |
| **Pixel 7a** | `lynx` | `CP3A.261005.002.A1` | **tested** |
| Pixel Fold | `felix` | `CP3A.261005.002.A1` | untested |
| Pixel Tablet | `tangorpro` | `CP3A.261005.002.A1` | untested |
| Pixel 8 | `shiba` | `CP3A.261005.005` | untested |
| Pixel 8 Pro | `husky` | `CP3A.261005.005` | untested |
| Pixel 8a | `akita` | `CP3A.261005.005` | untested |
| Pixel 9 | `tokay` | `CP3A.261005.005` | untested |
| Pixel 9 Pro | `caiman` | `CP3A.261005.005` | untested |
| Pixel 9 Pro XL | `komodo` | `CP3A.261005.005` | untested |
| Pixel 9 Pro Fold | `comet` | `CP3A.261005.005` | untested |
| **Pixel 9a** | `tegu` | `CP3A.261005.005` | **tested** |
| Pixel 10a | `stallion` | `CP3A.261005.005` | untested |

Every factory image in this table contains the same kernel payload: the 4K
`boot.img` kernel is byte-identical (16,637,222 bytes) across all 17 devices,
so this is the same binary, not merely the same version string.

Devices whose factory image also ships a `kernel_16k` (Pixel 8, 8 Pro, 8a, 9,
9 Pro, 9 Pro XL, 9a and 10a) can boot the 16K-page build of that same kernel.
Those images are byte-identical too, and the binary selects its offsets from
`sysconf(_SC_PAGESIZE)`, so it covers both the 4K and 16K layouts. The Pixel 9a
16K image was verified end-to-end in QEMU as well (`timer verify` and
`timer fake`).

### 6.6.127 (4K)

`6.6.127-android15-8-g91d825611104-ab16252310-4k`, shipped by the Pixel 10
series in the same `CP3A.261005.005` build number:

| Device | Codename | Status |
|---|---|---|
| **Pixel 10** | `frankel` | **verified in QEMU** |
| **Pixel 10 Pro** | `blazer` | **verified in QEMU** |
| **Pixel 10 Pro XL** | `mustang` | **verified in QEMU** |
| **Pixel 10 Pro Fold** | `rango` | **verified in QEMU** |

All four factory images contain a byte-identical kernel payload (36,866,560
bytes, SHA-256 `0226c3be4224b02884d4f9b332aee58ec06c65b2263265e80f2498332ef15c06`),
so one profile covers all of them. The 6.6 profile was verified end-to-end
(`timer verify` and `timer fake`) in a QEMU VM booting the factory kernel; it
has not been flashed on physical Pixel 10 hardware yet.

If your device is not in these tables, or its status is untested, run
`timer target` first and check that the reported `kernel=` matches. Do not run
the exploit on a kernel that does not match.

### 6.1.172 (4K) — Nothing Phone (3a)

`6.1.172-android14-11-g4538f521463f-ab16467005`, `asteroids` (A059, SM7635),
4K pages. Every constant was derived from that build's `boot.img`
(kallsyms + disassembly). Status: **tested**.

| Device | Codename | Kernel |
| --- | --- | --- |
| Nothing Phone (3a) | `asteroids` | `6.1.172-android14-11-g4538f521463f-ab16467005` |

Two things differ from the Pixel profiles:

- **The KASLR slide is 512 KB aligned here, not 2 MB.** The low 21 bits of the
  call site move at runtime, so `scan_timer_allocs()` and `scan_task_allocs()`
  match on 19 bits instead, and `calibrate_base()` rejects a slide that is not
  512 KB aligned.
- **`/data/adb` does not exist** on a device where KernelSU was only ever
  installed as an APK. The late-load script creates it before staging `ksud`.

## Build

### Android Studio / Gradle

Open the project and build, or:

```bash
./gradlew assembleDebug
```

The project needs the Android SDK with platform 36 and build-tools 36. The
Shizuku API is pulled from Maven (`dev.rikka.shizuku:api`).

### Without Gradle

`scripts/build.ps1` builds and signs an APK with just the SDK, `javac`, `d8`,
`aapt2` and `apksigner`. It vendors nothing: it compiles the app together with
the Shizuku API sources, so clone those first:

```powershell
git clone https://github.com/RikkaApps/Shizuku-API
scripts/build.ps1 -Sdk "C:\Users\<you>\AppData\Local\Android\Sdk"
```

## Usage

### 1. Start Shizuku

Shizuku has to be running before TimerRoot can do anything: it is the process
that provides the shell user the exploit needs. Shizuku stops on every reboot,
so this is the first step each time.

**Wireless debugging (no PC after the first pairing)**

1. Enable developer options: Settings -> About device -> tap *Build number* 7x.
2. Settings -> System -> Developer options -> **Wireless debugging** -> on.
3. Open the Shizuku app -> **Start** -> *Start via wireless debugging*.
4. Allow the notification, then in *Pair device with pairing code* enter the
   6-digit code shown on the phone.
5. Shizuku reports "Shizuku is running" (the notification says the server is up).

**Over USB**

With the phone connected and USB debugging authorised:

```bash
adb shell sh /sdcard/Android/data/moe.shizuku.privileged.api/start.sh
```

Newer Shizuku releases may not ship that script any more; if it is missing, use
the wireless debugging route above.

Check that the server is up:

```bash
adb shell ps -A | grep shizuku_server
# shell  12345  1  ...  shizuku_server
```

`ps` showing only `moe.shizuku.privileged.api` means the manager app is open but
the server is **not** running; the exploit cannot start until it is.

### 2. First launch

1. Open TimerRoot.
2. When Shizuku asks *Allow TimerRoot to access Shizuku?*, choose
   **Allow all the time**.
3. The card turns **Ready** (Shizuku connected, no root yet). If it still says
   `Not connected`, press `Shizuku` in the tools row to request again.

### 3. Install the binary

Press **Download exploit** to fetch the release asset, or `Prepare` to extract a
binary you built into `app/src/main/assets/timer`. Either path installs it to
`/data/local/tmp/timer` and then checks the target:

```
installed 2106912 bytes (uid=2000)
target=asteroids
kernel=6.1.162-android14-11-g9dd05ae3a1de-ab16261587
profile=4k
timer_site=0xffffffc0081932fc
```

`Diagnose` runs `timer ids`, which only probes the tracefs page event ids and
never touches the timer queue.

### 4. Get root shell

One tap. The app escalates, keeps a `uid=0` shell inside the service, and then
starts the KernelSU late-load automatically:

```
[child] woke uid=0
root shell ready - loading KernelSU...
Loading KernelSU... 12s
KSU_LOADED
```

The card goes **Root shell** -> **Jailbreak mode** (`u:r:ksu:s0`). The loader
finds the installed manager's `libksud.so` and loads that manager's module.
Known package names (`me.weishu.kernelsu`, `com.rifsxd.ksunext`,
`com.sukisu.ultra`) are tried first, then any package available to user 0 that
ships `libksud.so`. Repackaged managers with randomized package names are
supported, including builds that rename `libksud.so` to an unrelated `.so`
(it is identified by size and the `late-load` marker). The loader then compares
the manager's uapi version with the module the kernel reports (`ksud debug
info`). If a module from an earlier run is still loaded and its uapi does not
match, it prints `KSU_STALE` instead of pretending success: a kernel module
cannot be replaced without a reboot, and a mismatch is exactly what makes the
manager show `not installed` (for example KernelSU-Next's uapi 5 module with
SukiSU Ultra's uapi 6 manager). If the KernelSU stage loses its race, the card
turns red with `KernelSU failed`, and you should reboot before retrying.

KernelSU re-enables SELinux about half a second after it loads, so the app
immediately retries `su -c setenforce 0` (over ~12s) and confirms with
`getenforce`. A successful run therefore ends on `SELinux: Permissive`.

### 5. Reboot

Use the `Reboot` pill. It goes through the service (`svc power reboot`), so it
works even when no root shell is open yet. Rebooting is also the only clean way
to remove parked processes and to unload KernelSU.

After rebooting, TimerRoot can repeat the whole chain by itself: Shizuku is
stopped and KernelSU is gone, but the auto-root service starts Shizuku over a
localhost ADB channel while the device is still at the lock screen, binds it at
BFU and runs the exploit once per real boot.

### 6. Auto-root on boot

1. Get a root shell once (step 4).
2. Press **Install channel**. It runs `timer permissive` (clears the kernel's
   SELinux flag through the exploit), opens a root shell and appends
   `persist.adb.tcp.port=5555` to `/data/property/persistent_properties`, so
   adbd listens on localhost at every boot even with Wi-Fi off. It also
   disables the 7-day ADB key expiry. KernelSU is not required for this step.
3. Reboot. The first localhost connection shows the normal *Allow USB
   debugging?* dialog; tap **Always allow**. The key is then in `adb_keys`, so
   later boots use signature auth with no UI.

From then on a foreground service runs on every real boot.
`LOCKED_BOOT_COMPLETED` (seconds after the kernel starts) starts Shizuku over
`127.0.0.1:5555` and runs the exploit right away, before the user unlocks. This
works because TimerRoot's Shizuku provider is `directBootAware`: when
`shizuku_server` starts it hands its binder to every app that declares
`API_V23`, and with a direct-boot-aware provider that delivery also works while
credential-encrypted storage is still locked. If the binder does not arrive,
`BOOT_COMPLETED` retries after unlock; the per-boot guard still allows only one
exploit run. The service stays in the foreground to keep the root shell alive.
**Run auto-root now** repeats it on demand; the history is under
**Auto-root log**.

After the root shell is up, the boot path continues on its own: it runs
`timer fake` (the same endgame as **Load KernelSU** in step 4), which
late-loads the installed manager's module and clears the kernel's SELinux flag
in the same plant. The loader usually finishes within ~20 s of the exploit and
the notification changes to **Jailbreak mode ready**:

```
17:57:07  root shell ready; loading KernelSU
17:57:27  KernelSU attempt 2: the exploit parked before loading ksud
17:57:46  KernelSU active: selinux=Permissive (after 1s)
17:57:46  success: root shell ready; KernelSU active (selinux=Permissive (after 1s))
```

The plant is a race, so the stage is replanted up to three times; a missed
burst parks a process and leaves the boot usable, which is exactly what the
exploit itself does for `shell` and `permissive`. The last line is the result
stored in the auto-root log: `KernelSU active` means `/system/bin/su -c id`
reported `u:r:ksu:s0` and `getenforce` stayed `Permissive`. If the manager is
missing (or its module is incompatible) the root shell is kept and the
notification says `Root shell ready` with the KernelSU reason instead.

BFU is a normal operating point, not a fallback. A password-protected device
does not need to be unlocked first: the exploit runs at the lock screen and the
root shell is already waiting when you unlock. KernelSU is loaded at the same
point, so SukiSU/SukiSU Ultra and friends report an initialised manager as soon
as you unlock and open them.

Without the channel, auto-root still works when Shizuku is already running
(for example started by hand over Wi-Fi).

The status card reflects what is actually live, detected by running
`su -c id` and checking for `u:r:ksu:s0`:

| card | meaning |
|---|---|
| Not connected | Shizuku is not running / not bound |
| Ready | Shizuku connected, no root yet |
| Root shell | `uid=0`, `u:r:shell:s0` |
| Jailbreak mode | KernelSU loaded, `su` works in `u:r:ksu:s0` |


### `Failed to rename /data/local/tmp/.ksud-stage to /data/adb/ksud`

`/data/adb` is missing. The late-load script runs `mkdir -p /data/adb` before
staging. If it still fails, confirm the fake-cred stage reached full caps
(`CapEff: 000001ffffffffff` in the log) and that SELinux is permissive.

## Safety

This is a kernel exploit. Read this before pressing anything.

- **Do not kill a parked process.** The exploit keeps a process alive with the
  fake credential page pinned in socket buffers. Reaping it can panic the
  kernel. Reboot is the only clean way to remove it.
- **A reboot clears everything**: KernelSU, the root shell and the parked
  processes. That is the intended way to stop.
- **SELinux is left permissive** until the next reboot.
- A failed attempt leaves a stale timerqueue node; other apps may crash until
  you reboot.
- Only use this on a device you own or are explicitly allowed to modify.

## Layout

```
app/src/main/java/com/kpgc/timerroot/MainActivity.java        UI and state
app/src/main/java/com/kpgc/timerroot/UserService.java         runs as the shell user
app/src/main/java/com/kpgc/timerroot/AutoRootService.java     boot-time state machine
app/src/main/java/com/kpgc/timerroot/AutoRoot.java            guards, key and log
app/src/main/java/com/kpgc/timerroot/AdbLocal.java            minimal localhost ADB client
app/src/main/java/com/kpgc/timerroot/AdbKey.java              RSA key generation
app/src/main/java/com/kpgc/timerroot/BootReceiver.java        BOOT_COMPLETED entry point
app/src/main/java/com/kpgc/timerroot/RestartJobService.java   binder-push restart
app/src/main/aidl/com/kpgc/timerroot/IUserService.aidl        service interface
app/src/main/assets/timer                                     exploit binary (not in git)
scripts/build.ps1                                             Gradle-free build
docs/auto-root.md                                             research and field notes
```

## Credits

- Exploit: [YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260)
  (MIT), based on work by woshigenm and the other 98260 ports.
- [Shizuku](https://github.com/RikkaApps/Shizuku) and
  [Shizuku-API](https://github.com/RikkaApps/Shizuku-API) (Apache-2.0) by Rikka.
- KernelSU (GPL-2.0), KernelSU-Next, and SukiSU Ultra for the late-load path.
- Original repository that this fork based on: [kpgc10kai/TimerRoot](https://github.com/kpgc10kai/TimerRoot)
## License

MIT for the app code in this repository. The exploit binary and the Shizuku API
keep their own licenses.
