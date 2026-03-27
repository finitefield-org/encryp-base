package io.github.kazuyoshitoshiya.encrypbase.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EncSQLiteUserUnlockStateTest {
    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Test
    fun waitUntilAvailableReturnsCurrentAvailability() {
        val available = EncSQLiteUserUnlockState.isAvailable(context)

        assertEquals(available, EncSQLiteUserUnlockState.waitUntilAvailable(context, 0L))
    }
}
