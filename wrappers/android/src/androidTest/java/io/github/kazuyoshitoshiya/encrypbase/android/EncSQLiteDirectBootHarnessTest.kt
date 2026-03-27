package io.github.kazuyoshitoshiya.encrypbase.android

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EncSQLiteDirectBootHarnessTest {
    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Test
    fun deviceProtectedContextResolvesInsideDeviceProtectedStorage() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return
        }

        val deviceProtectedContext = EncSQLiteDirectBootHarness.deviceProtectedContext(context)
        val normalDatabaseFile = EncSQLiteDatabase.databaseFile(context, "encsqlite-direct-boot.db")
        val directBootDatabaseFile = EncSQLiteDatabase.databaseFile(
            deviceProtectedContext,
            "encsqlite-direct-boot.db"
        )

        assertTrue(deviceProtectedContext.isDeviceProtectedStorage)
        assertFalse(context.isDeviceProtectedStorage)
        assertNotEquals(normalDatabaseFile.absolutePath, directBootDatabaseFile.absolutePath)
        assertEquals("databases", directBootDatabaseFile.parentFile?.name)
    }

    @Test
    fun lockedBootReceiverWritesMarkerToDeviceProtectedStorage() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return
        }

        val markerFileName = "encsqlite-direct-boot-test.marker"
        val receiver = EncSQLiteDirectBootReceiver()
        val deviceProtectedContext = EncSQLiteDirectBootHarness.deviceProtectedContext(context)
        EncSQLiteDirectBootHarness.deleteLockedBootMarker(context, markerFileName)

        try {
            receiver.onReceive(
                deviceProtectedContext,
                Intent(Intent.ACTION_LOCKED_BOOT_COMPLETED).putExtra(
                    ENCSQLITE_DIRECT_BOOT_MARKER_FILE_NAME_EXTRA,
                    markerFileName
                )
            )

            val marker = EncSQLiteDirectBootHarness.readLockedBootMarker(context, markerFileName)
            assertNotNull(marker)
            assertTrue(marker!!.contains("action=android.intent.action.LOCKED_BOOT_COMPLETED"))
            assertTrue(marker.contains("deviceProtectedStorage=true"))
            assertTrue(marker.contains("userUnlocked="))
        } finally {
            EncSQLiteDirectBootHarness.deleteLockedBootMarker(context, markerFileName)
        }
    }
}
