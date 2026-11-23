package org.netmerge.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import org.netmerge.android.ui.MainScreen
import org.netmerge.android.ui.NetMergeTheme

class MainActivity : ComponentActivity() {
    private val notifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        Engine.loadSettings(this)
        setContent {
            NetMergeTheme {
                val phase by Engine.phase.collectAsState()
                val stats by Engine.stats.collectAsState()
                val history by Engine.history.collectAsState()
                val even by Engine.evenSplit.collectAsState()
                MainScreen(
                    phase = phase,
                    stats = stats,
                    history = history,
                    evenSplit = even,
                    onToggle = ::toggle,
                    onEvenSplit = { Engine.setEvenSplit(this, it) },
                )
            }
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (BuildConfig.DEBUG && intent.getBooleanExtra("autostart", false) &&
            Engine.phase.value == Engine.Phase.OFF
        ) toggle()
    }

    private fun toggle() {
        if (Engine.phase.value != Engine.Phase.OFF) MergeRootService.stop(this)
        else MergeRootService.start(this)
    }
}

