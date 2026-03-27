package io.github.kazuyoshitoshiya.encrypbase.android

import android.content.Context
import android.os.Build
import java.io.File

public const val ENCSQLITE_DIRECT_BOOT_MARKER_FILE_NAME = "encsqlite-direct-boot.marker"
public const val ENCSQLITE_DIRECT_BOOT_MARKER_FILE_NAME_EXTRA =
    "io.github.kazuyoshitoshiya.encrypbase.android.extra.MARKER_FILE_NAME"

public object EncSQLiteDirectBootHarness {
    @JvmStatic
    public fun deviceProtectedContext(context: Context): Context {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return context.applicationContext
        }

        return context.createDeviceProtectedStorageContext() ?: context.applicationContext
    }

    @JvmStatic
    public fun markerFile(
        context: Context,
        markerFileName: String = ENCSQLITE_DIRECT_BOOT_MARKER_FILE_NAME
    ): File {
        require(markerFileName.isNotBlank()) { "marker file name must not be blank" }
        require(!markerFileName.contains('/')) { "marker file name must not contain path separators" }
        require(!markerFileName.contains('\\')) { "marker file name must not contain path separators" }
        return deviceProtectedContext(context).getFileStreamPath(markerFileName)
    }

    @JvmStatic
    public fun writeLockedBootMarker(
        context: Context,
        markerFileName: String = ENCSQLITE_DIRECT_BOOT_MARKER_FILE_NAME
    ): File {
        val deviceProtectedContext = deviceProtectedContext(context)
        val markerFile = markerFile(context, markerFileName)
        val contents = buildString {
            appendLine("action=android.intent.action.LOCKED_BOOT_COMPLETED")
            appendLine("deviceProtectedStorage=${deviceProtectedContext.isDeviceProtectedStorage}")
            appendLine("userUnlocked=${EncSQLiteUserUnlockState.isAvailable(deviceProtectedContext)}")
        }
        markerFile.parentFile?.mkdirs()
        markerFile.writeText(contents)
        return markerFile
    }

    @JvmStatic
    public fun readLockedBootMarker(
        context: Context,
        markerFileName: String = ENCSQLITE_DIRECT_BOOT_MARKER_FILE_NAME
    ): String? {
        val marker = markerFile(context, markerFileName)
        if (!marker.exists()) {
            return null
        }
        return marker.readText()
    }

    @JvmStatic
    public fun deleteLockedBootMarker(
        context: Context,
        markerFileName: String = ENCSQLITE_DIRECT_BOOT_MARKER_FILE_NAME
    ): Boolean {
        return markerFile(context, markerFileName).delete()
    }
}
