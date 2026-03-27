package io.github.kazuyoshitoshiya.encrypbase.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

public class EncSQLiteDirectBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_LOCKED_BOOT_COMPLETED -> {
                val markerFileName = intent.getStringExtra(ENCSQLITE_DIRECT_BOOT_MARKER_FILE_NAME_EXTRA)
                if (markerFileName.isNullOrBlank()) {
                    EncSQLiteDirectBootHarness.writeLockedBootMarker(context)
                } else {
                    EncSQLiteDirectBootHarness.writeLockedBootMarker(context, markerFileName)
                }
            }
        }
    }
}
