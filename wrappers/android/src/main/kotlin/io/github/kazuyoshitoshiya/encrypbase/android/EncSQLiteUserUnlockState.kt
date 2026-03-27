package io.github.kazuyoshitoshiya.encrypbase.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.UserManager
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

public object EncSQLiteUserUnlockState {
    @JvmStatic
    public fun isAvailable(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return true
        }

        val userManager = context.getSystemService(UserManager::class.java)
        return userManager?.isUserUnlocked ?: true
    }

    @JvmStatic
    public fun waitUntilAvailable(context: Context, timeoutMillis: Long): Boolean {
        if (isAvailable(context)) {
            return true
        }
        if (timeoutMillis <= 0L) {
            return false
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return true
        }

        val appContext = context.applicationContext
        val latch = CountDownLatch(1)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (Intent.ACTION_USER_UNLOCKED == intent?.action) {
                    latch.countDown()
                }
            }
        }

        @Suppress("DEPRECATION")
        appContext.registerReceiver(receiver, IntentFilter(Intent.ACTION_USER_UNLOCKED))
        try {
            latch.await(timeoutMillis, TimeUnit.MILLISECONDS)
            return isAvailable(appContext)
        } finally {
            @Suppress("DEPRECATION")
            appContext.unregisterReceiver(receiver)
        }
    }
}
