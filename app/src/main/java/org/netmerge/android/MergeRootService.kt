package org.netmerge.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.service.quicksettings.TileService
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Root mode: no VpnService, so Android's VPN slot stays available for Tailscale.
 * The helper supplies a root-created TUN FD and adds a policy rule at priority
 * 23123, after VPN routing but before normal physical-network fallback.
 */
class MergeRootService : Service() {
    companion object {
        const val ACTION_START = "org.netmerge.android.root.START"
        const val ACTION_STOP = "org.netmerge.android.root.STOP"
        private const val TAG = "NetMergeRoot"
        private const val CHANNEL = "status"
        private const val NOTIF_ID = 1
        private const val MTU = 9000
        private const val NETWORK_WAIT_MS = 3000L

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, MergeRootService::class.java).setAction(ACTION_START))
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, MergeRootService::class.java).setAction(ACTION_STOP))
        }
    }

    @Volatile private var wanted = false
    private var tracker: NetworkTracker? = null
    private var bridge: RootTunBridge? = null
    private var session: RootTunSession? = null
    private var starting = false
    private var ticks = 0
    private val main = Handler(Looper.getMainLooper())
    private val refresh = object : Runnable {
        override fun run() {
            if (Engine.phase.value != Engine.Phase.ON) return
            Engine.sample()
            if (ticks++ % 2 == 0) updateNotification()
            main.postDelayed(this, 1000)
        }
    }
    private val establishAnyway = Runnable { establish() }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        goForeground()
        if (Engine.phase.value == Engine.Phase.OFF) begin()
        return START_STICKY
    }

    private fun begin() {
        wanted = true
        starting = false
        ticks = 0
        Engine.setPhase(Engine.Phase.STARTING)
        Engine.loadSettings(this)
        requestTileUpdate()
        val t = NetworkTracker(this) { nets -> main.post { onNetworks(nets) } }
        tracker = t
        t.start()
        main.postDelayed(establishAnyway, NETWORK_WAIT_MS)
    }

    private fun establish() {
        main.removeCallbacks(establishAnyway)
        if (!wanted || Engine.phase.value != Engine.Phase.STARTING || starting) return
        starting = true
        val b = RootTunBridge()
        bridge = b
        pushNetworks(tracker?.current().orEmpty())
        thread(name = "netmerge-root-start", isDaemon = true) {
            var opened: RootTunSession? = null
            var goStarted = false
            try {
                opened = b.open(this)
                check(wanted) { "Start cancelled" }
                netmerge.Netmerge.start(opened.takeTunFd().toLong(), MTU.toLong())
                goStarted = true
                check(wanted) { "Start cancelled" }
                opened.activate()
                check(wanted) { "Start cancelled" }
                val ready = requireNotNull(opened)
                main.post {
                    if (wanted && Engine.phase.value == Engine.Phase.STARTING) {
                        session = ready
                        Engine.setPhase(Engine.Phase.ON)
                        main.post(refresh)
                        requestTileUpdate()
                        updateNotification()
                    } else {
                        runCatching { netmerge.Netmerge.stop() }
                        ready.close()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Root mode startup failed", e)
                if (goStarted) runCatching { netmerge.Netmerge.stop() }
                runCatching { opened?.close() }
                main.post {
                    if (wanted && Engine.phase.value == Engine.Phase.STARTING) shutdown()
                }
            }
        }
    }

    private fun onNetworks(nets: List<NetworkTracker.Tracked>) {
        if (!wanted) return
        pushNetworks(nets)
        if (Engine.phase.value == Engine.Phase.STARTING && !starting && nets.isNotEmpty()) {
            establish()
        }
        if (Engine.phase.value == Engine.Phase.ON) updateNotification()
    }

    private fun pushNetworks(nets: List<NetworkTracker.Tracked>) {
        val arr = JSONArray()
        for (n in nets) {
            arr.put(
                JSONObject()
                    .put("name", n.name)
                    .put("handle", n.network.networkHandle.toString())
                    .put("v4", n.v4)
                    .put("v6", n.v6)
                    .put("downKbps", n.downKbps),
            )
        }
        runCatching { netmerge.Netmerge.setNetworks(arr.toString()) }
            .onFailure { Log.e(TAG, "setNetworks", it) }
    }

    private fun shutdown() {
        wanted = false
        main.removeCallbacks(refresh)
        main.removeCallbacks(establishAnyway)
        bridge?.cancel()
        bridge = null
        if (Engine.phase.value == Engine.Phase.ON) {
            runCatching { netmerge.Netmerge.stop() }
        }
        session?.close()
        session = null
        starting = false
        tracker?.stop()
        tracker = null
        Engine.setPhase(Engine.Phase.OFF)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        requestTileUpdate()
    }

    override fun onDestroy() {
        if (Engine.phase.value != Engine.Phase.OFF) shutdown()
        super.onDestroy()
    }

    private fun requestTileUpdate() {
        TileService.requestListeningState(this, ComponentName(this, MergeTileService::class.java))
    }

    private fun goForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW),
        )
        val n = buildNotification(getString(R.string.notif_waiting))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun buildNotification(content: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, MergeRootService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_merge)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(content)
            .setStyle(Notification.BigTextStyle().bigText(content))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, getString(R.string.stop), stop).build())
            .build()
    }

    private fun updateNotification() {
        if (Engine.phase.value != Engine.Phase.ON) return
        val stats = Engine.stats.value
        val content = if (stats.isEmpty()) getString(R.string.notif_waiting)
        else stats.joinToString("\n") { it.name + ": " + Stats.rate(it.rateIn + it.rateOut) + " / " + it.status }
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(content))
    }
}


