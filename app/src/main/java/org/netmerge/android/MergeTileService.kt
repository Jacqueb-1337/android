package org.netmerge.android

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Root mode needs no VPN consent. */
class MergeTileService : TileService() {
    override fun onStartListening() = refresh()
    override fun onClick() {
        if (Engine.phase.value != Engine.Phase.OFF) MergeRootService.stop(this)
        else MergeRootService.start(this)
        refresh()
    }
    private fun refresh() {
        val tile = qsTile ?: return
        tile.state = if (Engine.phase.value != Engine.Phase.OFF) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.updateTile()
    }
}

