package com.kpgc.timerroot;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.os.IBinder;
import android.os.PowerManager;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import rikka.shizuku.Shizuku;

/**
 * Boot-time state machine:
 *
 *   wait for Shizuku -> start it over the local ADB channel if needed ->
 *   bind the shell user service -> install the bundled exploit -> run it once
 *   -> late-load KernelSU and re-apply permissive.
 *
 * This runs from LOCKED_BOOT_COMPLETED, so it normally completes before the
 * first unlock (BFU). The Shizuku provider is directBootAware, which is what
 * lets the server deliver its binder while the user is still locked.
 *
 * The service stays in the foreground after success, because the root shell
 * lives in the Shizuku user service and that service is tied to this app
 * process. Stopping the service would throw the root shell away.
 */
public class AutoRootService extends Service {

    static final String ACTION_START = "com.kpgc.timerroot.AUTOROOT_START";
    static final String ACTION_STOP = "com.kpgc.timerroot.AUTOROOT_STOP";
    static final String ACTION_RUN_NOW = "com.kpgc.timerroot.AUTOROOT_RUN_NOW";
    static final String ACTION_PRESTART = "com.kpgc.timerroot.AUTOROOT_PRESTART";

    private static final String CHANNEL = "auto_root";
    private static final int NOTIFICATION_ID = 41;
    private static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";

    private Thread worker;
    private PowerManager.WakeLock wakeLock;
    private Shizuku.UserServiceArgs boundArgs;
    private ServiceConnection boundConnection;
    private IUserService userService;
    /** True once this service instance has called startForeground(). */
    private boolean foregroundStarted;
    /** True once the exploit has actually been started this boot. */
    private boolean exploitStarted;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        /*
         * A duplicate boot broadcast, or a second start after a successful
         * run, must not replace the live notification or touch the root
         * shell. Stop a freshly created service (which also cancels the
         * startForegroundService deadline); leave an already running one
         * exactly as it is.
         */
        if (!ACTION_RUN_NOW.equals(action)
                && AutoRoot.isBootClaimed(this)
                && !AutoRoot.hasPendingRestart(this)) {
            AutoRoot.log(this, "already attempted this boot, ignoring " + action);
            if (!foregroundStarted) {
                stopSelf(startId);
            }
            return START_NOT_STICKY;
        }
        startForeground(NOTIFICATION_ID, notification(
                "Auto-root", "preparing...", true));
        foregroundStarted = true;

        final boolean force = ACTION_RUN_NOW.equals(action);
        final boolean prestart = ACTION_PRESTART.equals(action);
        synchronized (this) {
            Thread previous = worker;
            Thread next = new Thread(() -> {
                if (previous != null) {
                    try {
                        // A prestart may still be running; run after it.
                        previous.join();
                    } catch (InterruptedException ignored) {
                    }
                }
                if (prestart) {
                    startShizukuEarly();
                }
                run(force);
            }, "auto-root");
            next.start();
            worker = next;
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        releaseWakeLock();
        if (boundArgs != null && boundConnection != null) {
            try {
                // Keep the user service: an open root shell lives inside it.
                Shizuku.unbindUserService(boundArgs, boundConnection, false);
            } catch (Throwable ignored) {
            }
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // ------------------------------------------------------------- worker

    /**
     * Starts Shizuku as early as possible (LOCKED_BOOT_COMPLETED), before the
     * normal boot attempt. The service then continues straight into
     * {@link #run(boolean)}: with a direct-boot-aware provider the server can
     * hand over its binder while the credential-encrypted user is still
     * locked, so there is no reason to wait for the unlock.
     */
    private void startShizukuEarly() {
        if (!AutoRoot.isEnabled(this)) {
            return;
        }
        AutoRoot.log(this, "prestart: looking for Shizuku");
        if (waitForShizuku(5000)) {
            AutoRoot.log(this, "prestart: Shizuku is already running");
            return;
        }
        acquireWakeLock();
        try {
            /*
             * This runs seconds after the boot broadcast, when parts of the
             * system are still starting up. A starter call can therefore
             * return before the server is actually there, so retry a few
             * times instead of giving up on the first try.
             */
            for (int attempt = 1; attempt <= 4; attempt++) {
                show("Auto-root", "starting Shizuku early (try " + attempt + ")...");
                String started = startShizuku();
                AutoRoot.log(this, "prestart starter " + attempt + ": " + started);
                long deadline = System.currentTimeMillis() + 15000;
                boolean up = false;
                while (System.currentTimeMillis() < deadline) {
                    if (waitForShizuku(1500)) {
                        AutoRoot.log(this, "prestart: Shizuku is up");
                        up = true;
                        break;
                    }
                    if (shizukuServerRunning()) {
                        AutoRoot.log(this, "prestart: server is up, waiting for its binder");
                        up = true;
                        break;
                    }
                }
                if (up) {
                    break;
                }
                AutoRoot.log(this, "prestart: server still not up after try " + attempt);
            }
        } catch (Throwable t) {
            AutoRoot.log(this, "prestart failed: " + t);
        } finally {
            releaseWakeLock();
        }
    }

    private void run(boolean force) {
        SharedPreferences prefs = AutoRoot.prefs(this);
        if (!prefs.getBoolean(AutoRoot.KEY_ENABLED, false)) {
            AutoRoot.log(this, "auto-root is disabled, stopping");
            finish("Auto-root is off", "Enable it in TimerRoot first.", false);
            return;
        }
        boolean restarted = AutoRoot.consumeRestart(this);
        boolean firstAttempt = AutoRoot.claimBoot(this);
        if (!force && !restarted && !firstAttempt) {
            AutoRoot.log(this, "already attempted this boot, skipping");
            if (userService != null
                    && AutoRoot.lastResult(this).startsWith("root shell ready")) {
                // Keep the successful run, its root shell and its FGS alive.
                String last = AutoRoot.lastResult(this);
                finish(last.contains("KernelSU active")
                                ? "Jailbreak mode ready" : "Root shell ready",
                        last, true);
            } else {
                finish("Auto-root", "Already ran this boot.", false);
                stopSelf();
            }
            return;
        }
        if (restarted) {
            AutoRoot.log(this, "resuming this boot after the binder restart");
        }
        acquireWakeLock();

        String result;
        exploitStarted = false;
        try {
            result = attempt();
        } catch (Throwable t) {
            result = "unexpected error: " + t;
        } finally {
            releaseWakeLock();
        }
        if (result == null) {
            // The process is about to die so the uid can go active again.
            return;
        }
        if (!exploitStarted) {
            /*
             * Nothing destructive ran, so this boot may still try again after
             * the unlock (or when the user presses Run auto-root now). The
             * one-exploit-per-boot guard is only spent by the exploit itself.
             */
            AutoRoot.releaseBoot(this);
        }
        AutoRoot.clearRestart(this);
        AutoRoot.record(this, result);
        boolean success = result.startsWith("root shell ready");
        AutoRoot.log(this, (success ? "success: " : "failed: ") + result);
        if (success) {
            boolean ksu = result.contains("KernelSU active");
            // Stay alive to keep the Shizuku user service (and the root shell).
            finish(ksu ? "Jailbreak mode ready" : "Root shell ready",
                    ksu ? "KernelSU late-loaded; su works in u:r:ksu:s0."
                            : summary(result), true);
        } else {
            stopForeground(STOP_FOREGROUND_DETACH);
            finish("Auto-root failed", summary(result), false);
            stopSelf();
        }
    }

    private String attempt() throws Exception {
        String started = null;
        /*
         * No unlock wait here. The provider is directBootAware, so
         * shizuku_server can deliver its binder to this app while the
         * credential-encrypted user is still locked, and the shell user
         * service lives in device-encrypted storage as well. Running the
         * exploit at BFU is the whole point of the boot path.
         */
        boolean binder = waitForShizuku(15000);
        boolean serverUp = false;
        if (binder) {
            AutoRoot.log(this, "Shizuku is already running");
            serverUp = true;
        } else {
            /*
             * The prestart stage (LOCKED_BOOT_COMPLETED) usually started the
             * server already. Do not restart a healthy server: the starter
             * kills the old process first, which would throw the early start
             * away.
             */
            serverUp = shizukuServerRunning();
            if (serverUp) {
                AutoRoot.log(this, "Shizuku server is already up from the prestart");
            } else {
                show("Auto-root", "starting Shizuku over the local ADB channel...");
                started = startShizuku();
                AutoRoot.log(this, "starter: " + started);
                long deadline = System.currentTimeMillis() + 45000;
                while (System.currentTimeMillis() < deadline) {
                    if (waitForShizuku(1500)) {
                        binder = true;
                        serverUp = true;
                        break;
                    }
                    if (shizukuServerRunning()) {
                        serverUp = true;
                        break;
                    }
                }
            }
        }

        if (!binder) {
            if (!serverUp) {
                return "Shizuku did not start ("
                        + (started == null ? "already running" : started) + ")";
            }
            if (!userUnlocked()) {
                /*
                 * The server hands its binder to every permission-holding
                 * app when it starts, through the direct-boot-aware
                 * provider. If it is still missing, do not rely on a
                 * JobScheduler restart that Android may defer until the
                 * unlock; leave the boot claim free so the post-unlock
                 * BOOT_COMPLETED can try again in a fresh process.
                 */
                return "Shizuku is up but its binder has not arrived; retrying after unlock";
            }
            /*
             * The server is up but has no idea this app exists: it only
             * pushes the binder on a uid gone -> active transition. Kill the
             * process once per boot and let a scheduled job start it again.
             */
            if (!AutoRoot.claimRestart(this)) {
                return "Shizuku is running but did not push its binder";
            }
            AutoRoot.log(this, "server is up, no binder yet; restarting the app process");
            show("Auto-root", "restarting to receive the Shizuku binder...");
            RestartJobService.schedule(this);
            killSelf();
            return null;
        }

        AutoRoot.clearRestart(this);
        int permission;
        try {
            permission = Shizuku.checkSelfPermission();
        } catch (Throwable t) {
            permission = -1;
        }
        if (permission != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return "Shizuku permission is not granted - open TimerRoot and allow it once";
        }

        show("Auto-root", "binding the shell user service...");
        IUserService service = bindUserService();
        if (service == null) {
            return "could not bind the Shizuku user service";
        }

        String installed = service.install(getPackageCodePath());
        AutoRoot.log(this, installed);
        if (!installed.startsWith("installed")) {
            return "could not install the bundled exploit: " + installed;
        }
        String target = service.run("target");
        if (!target.contains("target=asteroids")) {
            return "bundled exploit rejected for this kernel: " + target.trim();
        }

        show("Auto-root", "running the exploit...");
        AutoRoot.log(this, "timer shell");
        exploitStarted = true;
        String output = service.openRoot();
        if (!output.startsWith("root shell ready")) {
            return "exploit did not reach uid=0: " + tail(output);
        }
        /*
         * The shell-domain root cannot keep KernelSU loaded across a boot, so
         * the chain does not stop here: the fake-credential endgame late-loads
         * the installed manager's module, exactly like the manual "Get root
         * shell" button does. A KSU failure must not throw away the working
         * root shell, hence the separate result suffix.
         */
        AutoRoot.log(this, "root shell ready; loading KernelSU");
        show("Auto-root", "loading KernelSU...");
        return "root shell ready; " + loadKernelSu(service);
    }

    /** How many times the racy late-load stage may be replanted. */
    private static final int KSU_ATTEMPTS = 3;

    private static final class KsuStage {
        boolean loaded;
        String failure;
        /** True when the plant lost its race and nothing was loaded yet. */
        boolean replant;
    }

    /**
     * Runs `timer fake`, which points the child's credentials at a fake
     * full-capability cred and execs ksud late-load. That same plant also
     * clears the kernel's SELinux enforcing flag, so no separate
     * `timer permissive` run is needed.
     *
     * The stage shell can be torn down by the loader (SukiSU Ultra) before it
     * prints KSU_LOADED, so `su -c id` in u:r:ksu:s0 is the authoritative
     * success signal. KernelSU re-enables SELinux about 0.4s after it loads,
     * which is why keepPermissive() runs afterwards.
     *
     * A plant can miss its burst and park a zombie; the exploit itself
     * replants up to three times in `shell`/`permissive` mode for exactly
     * that reason, so the whole stage is replanted here too. A parked
     * process keeps its fake cred page pinned, which is the pristine state
     * between attempts.
     */
    private String loadKernelSu(IUserService service) {
        String failure = "no attempt was made";
        try {
            for (int attempt = 1; attempt <= KSU_ATTEMPTS; attempt++) {
                if (attempt > 1) {
                    AutoRoot.log(this, "KernelSU attempt " + attempt + ": "
                            + failure);
                    show("Auto-root", "retrying KernelSU (" + attempt + "/"
                            + KSU_ATTEMPTS + ")...");
                }
                KsuStage stage = runKsuStage(service, attempt);
                if (stage.loaded) {
                    String selinux = service.keepPermissive();
                    AutoRoot.log(this, "KernelSU active: " + selinux);
                    AutoRoot.log(this, tail(service.readLog()));
                    return "KernelSU active (" + selinux + ")";
                }
                AutoRoot.log(this, tail(service.readLog()));
                failure = stage.failure;
                if (!stage.replant) {
                    break;
                }
            }
        } catch (Throwable t) {
            AutoRoot.log(this, "KernelSU step failed: " + t);
            return "KernelSU failed: " + t;
        }
        return "KernelSU failed: " + failure;
    }

    private KsuStage runKsuStage(IUserService service, int attempt) {
        KsuStage stage = new KsuStage();
        try {
            /*
             * runDetached() truncates /data/local/tmp/timer.log, so anything
             * read from here on belongs to this run.
             */
            String started = service.runDetached("fake");
            AutoRoot.log(this, "timer fake");
            if (started.startsWith("start failed")) {
                stage.failure = tail(started);
                return stage;
            }
            final long startedAt = System.currentTimeMillis();
            long lastChange = startedAt;
            long lastProgress = 0;
            int lastLength = -1;
            boolean sawLateLoad = false;
            while (System.currentTimeMillis() - startedAt < 90000) {
                Thread.sleep(1000);
                String log = service.readLog();
                if (log.length() != lastLength) {
                    lastLength = log.length();
                    lastChange = System.currentTimeMillis();
                }
                if (log.contains("KSU_LOADED")) {
                    stage.loaded = true;
                    return stage;
                }
                if (log.contains("selinux write failed")) {
                    stage.failure = "the selinux stage missed its race";
                    stage.replant = true;
                    return stage;
                }
                if (log.contains("KSU_STALE")) {
                    stage.failure = "an old KernelSU module is still loaded";
                    return stage;
                }
                if (log.contains("[ksu] ksud missing")) {
                    stage.failure = "no supported manager (KernelSU,"
                            + " KernelSU-Next, SukiSU)";
                    return stage;
                }
                if (log.contains("KSU_MISSING")) {
                    stage.failure = "ksud late-load failed - see the [ksu]"
                            + " log lines";
                    return stage;
                }
                if (log.contains("[ksu] late-load rc=0")) {
                    sawLateLoad = true;
                }
                /*
                 * The exploit parent always parks, even on success, so the
                 * parking line alone means nothing. Once the late-load has
                 * run, ask the kernel whether root actually works.
                 */
                if (log.contains("parking without reap")) {
                    if (sawLateLoad && service.ksuActive()) {
                        stage.loaded = true;
                    } else if (sawLateLoad) {
                        stage.failure = "ksud finished but su is not available";
                    } else {
                        stage.failure = "the exploit parked before loading"
                                + " ksud";
                        stage.replant = true;
                    }
                    return stage;
                }
                if (sawLateLoad
                        && System.currentTimeMillis() - lastChange > 5000) {
                    if (service.ksuActive()) {
                        stage.loaded = true;
                    } else {
                        stage.failure = "ksud late-load finished but su is"
                                + " not available";
                    }
                    return stage;
                }
                long secs = (System.currentTimeMillis() - startedAt) / 1000;
                if (secs - lastProgress >= 5) {
                    lastProgress = secs;
                    String label = attempt > 1 ? " (" + attempt + "/"
                            + KSU_ATTEMPTS + ")" : "";
                    show("Auto-root", "loading KernelSU... " + secs + "s" + label);
                }
            }
            if (service.ksuActive()) {
                // Last chance: the stage may have lost its output.
                stage.loaded = true;
                return stage;
            }
            stage.failure = "timed out after 90s";
            return stage;
        } catch (Throwable t) {
            AutoRoot.log(this, "KernelSU step failed: " + t);
            stage.failure = String.valueOf(t);
            return stage;
        }
    }

    /**
     * True once the user has unlocked at least once since boot. Used only to
     * decide whether the binder restart fallback can run; the normal BFU path
     * does not depend on it.
     */
    private boolean userUnlocked() {
        android.os.UserManager um = getSystemService(android.os.UserManager.class);
        return um == null || um.isUserUnlocked();
    }

    private boolean waitForShizuku(long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (Shizuku.pingBinder()) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                return false;
            }
        }
        return false;
    }

    /**
     * Ends this process so the next start of the app is a uid gone -> active
     * transition. The scheduled job survives the kill and starts us again.
     */
    private void killSelf() {
        releaseWakeLock();
        try {
            Thread.sleep(250);
        } catch (InterruptedException ignored) {
        }
        android.os.Process.killProcess(android.os.Process.myPid());
    }

    /**
     * True when shizuku_server is alive, checked over the local ADB channel.
     * The server daemonizes, so its pid is not a child of the starter call.
     */
    private boolean shizukuServerRunning() {
        try {
            KeyPair pair = AutoRoot.keyPair(this);
            AdbLocal.Result result = AdbLocal.shell("127.0.0.1", AutoRoot.adbPort(this),
                    pair.getPrivate(), (RSAPublicKey) pair.getPublic(),
                    "pidof shizuku_server", 15000);
            return result.finished && result.output.trim().matches("[0-9]+");
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Runs Shizuku's own starter as the shell user over adbd. This is exactly
     * what Shizuku's wireless-debugging boot path does, except the port is
     * fixed (persist.adb.tcp.port) and comes from adb_keys, not mDNS.
     */
    private String startShizuku() {
        try {
            KeyPair pair = AutoRoot.keyPair(this);
            String command = "P=$(pm path " + SHIZUKU_PACKAGE + " | head -n1 | cut -d: -f2); "
                    + "D=$(dirname \"$P\"); "
                    + "L=$(ls \"$D\"/lib/*/libshizuku.so 2>/dev/null | head -n1); "
                    + "echo \"apk=$P\"; echo \"lib=$L\"; "
                    + "[ -x \"$L\" ] || { echo NO_STARTER; exit 1; }; "
                    + "\"$L\" --apk=\"$P\"; echo STARTER_DONE";
            AdbLocal.Result result = AdbLocal.shell("127.0.0.1", AutoRoot.adbPort(this),
                    pair.getPrivate(), (RSAPublicKey) pair.getPublic(),
                    command, 45000);
            String output = result.output == null ? "" : result.output.trim();
            AutoRoot.log(this, "adb starter raw: " + (output.isEmpty() ? "(no output)" : tail(output)));
            if (result.needsAuthorization) {
                return "TimerRoot's ADB key is not authorized yet - connect it once"
                        + " from a computer or tap Allow on the device";
            }
            if (result.finished) {
                return "launched";
            }
            String error = result.error == null ? "no response" : result.error;
            return "adb: " + error + (output.isEmpty() ? "" : " / " + output);
        } catch (Throwable t) {
            return "adb failed: " + t;
        }
    }

    private IUserService bindUserService() {
        final CountDownLatch latch = new CountDownLatch(1);
        final IUserService[] holder = new IUserService[1];
        final Shizuku.UserServiceArgs args = AutoRoot.serviceArgs(this);
        ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder binder) {
                holder[0] = IUserService.Stub.asInterface(binder);
                latch.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                AutoRoot.log(AutoRootService.this, "user service disconnected");
            }
        };
        try {
            Shizuku.bindUserService(args, connection);
            if (!latch.await(20, TimeUnit.SECONDS)) {
                return null;
            }
            boundArgs = args;
            boundConnection = connection;
            userService = holder[0];
            return holder[0];
        } catch (Throwable t) {
            AutoRoot.log(this, "bind failed: " + t);
            return null;
        }
    }

    // -------------------------------------------------------- notification

    private void createChannel() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(CHANNEL, "Auto-root",
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Boot-time root attempt state");
        channel.enableVibration(false);
        channel.setShowBadge(false);
        manager.createNotificationChannel(channel);
    }

    private Notification notification(String title, String text, boolean ongoing) {
        PendingIntent open = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                                | Intent.FLAG_ACTIVITY_CLEAR_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setOnlyAlertOnce(true)
                .setOngoing(ongoing);
        if (ongoing) {
            PendingIntent stop = PendingIntent.getService(this, 1,
                    new Intent(this, AutoRootService.class)
                            .setAction(ACTION_STOP),
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            builder.addAction(new Notification.Action.Builder(null, "Stop", stop).build());
        }
        return builder.build();
    }

    private void show(String title, String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification(title, text, true));
        }
    }

    private void finish(String title, String text, boolean keepRunning) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification(title, text, keepRunning));
        }
        if (!keepRunning) {
            stopForeground(STOP_FOREGROUND_DETACH);
        }
    }

    private static String summary(String result) {
        return result.length() > 120 ? result.substring(0, 117) + "..." : result;
    }

    private static String tail(String output) {
        String trimmed = output.trim();
        if (trimmed.length() <= 400) {
            return trimmed;
        }
        return "..." + trimmed.substring(trimmed.length() - 400);
    }

    // ------------------------------------------------------------- wake lock

    private void acquireWakeLock() {
        try {
            PowerManager power = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (power == null || wakeLock != null) {
                return;
            }
            wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                    "TimerRoot:auto-root");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire(10 * 60 * 1000L);
        } catch (Throwable ignored) {
        }
    }

    private void releaseWakeLock() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) {
                wakeLock.release();
            }
        } catch (Throwable ignored) {
        }
        wakeLock = null;
    }
}
