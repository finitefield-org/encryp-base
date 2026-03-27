package io.github.kazuyoshitoshiya.encrypbase.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EncSQLiteAndroidStorageTest {
    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Test
    fun databaseFileResolvesInsideAppPrivateStorage() {
        val databaseName = "encsqlite-instrumented.db"
        val databaseFile = EncSQLiteDatabase.databaseFile(context, databaseName)

        assertTrue(databaseFile.isAbsolute)
        assertTrue(databaseFile.absolutePath.startsWith(context.applicationInfo.dataDir))
        assertEquals("databases", databaseFile.parentFile?.name)
    }

    @Test
    fun keyStorePersistsWrappedBlobUnderInternalStorage() {
        val keyStoreOptions = EncSQLiteKeyStoreOptions(
            wrappedKeyFileName = "encsqlite-instrumented-wrapped-dek.bin",
            strongBoxPreferred = false
        )
        val keyStore = EncSQLiteKeyStore(context, keyStoreOptions)
        val original = EncSQLiteKeyMaterial.raw32(ByteArray(32) { (it + 1).toByte() })

        try {
            keyStore.saveKeyMaterial(original)

            val blobFile = context.getFileStreamPath(keyStoreOptions.wrappedKeyFileName)
            assertTrue(blobFile.isFile)
            assertTrue(blobFile.absolutePath.startsWith(context.filesDir.absolutePath))
            assertTrue(keyStore.hasStoredKeyMaterial())

            val loaded = keyStore.loadKeyMaterial()
            require(loaded != null) { "key material should load after being saved" }
            try {
                assertTrue(original.contentEquals(loaded))

                val reloaded = keyStore.loadOrCreateKeyMaterial()
                try {
                    assertTrue(original.contentEquals(reloaded))
                } finally {
                    reloaded.close()
                }
            } finally {
                loaded.close()
            }
        } finally {
            original.close()
            keyStore.deleteKeyMaterial()
            assertFalse(keyStore.hasStoredKeyMaterial())
        }
    }

    @Test
    fun keyStoreLoadOrCreateCanWaitForUnlock() {
        val keyStore = EncSQLiteKeyStore(context)
        val keyMaterial = EncSQLiteKeyMaterial.raw32(ByteArray(32) { 0x41 })
        var observedTimeout = -1L

        try {
            keyStore.saveKeyMaterial(keyMaterial)

            val loaded = keyStore.loadOrCreateKeyMaterial(
                waitForUserUnlockTimeoutMillis = 250L
            ) { _, timeoutMillis ->
                observedTimeout = timeoutMillis
                true
            }

            try {
                assertTrue(loaded.contentEquals(keyMaterial))
                assertEquals(250L, observedTimeout)
            } finally {
                loaded.close()
            }
        } finally {
            keyMaterial.close()
            keyStore.deleteKeyMaterial()
        }
    }

    @Test
    fun keyStoreLoadOrCreateFailsWhenUnlockNeverArrives() {
        val keyStore = EncSQLiteKeyStore(context)

        try {
            try {
                keyStore.loadOrCreateKeyMaterial(
                    waitForUserUnlockTimeoutMillis = 250L
                ) { _, timeoutMillis ->
                    assertEquals(250L, timeoutMillis)
                    false
                }
                throw AssertionError("expected loadOrCreateKeyMaterial to fail")
            } catch (error: IllegalStateException) {
                assertTrue(error.message?.contains("user unlock") == true)
            }
        } finally {
            keyStore.deleteKeyMaterial()
        }
    }
}
