package io.github.kazuyoshitoshiya.encrypbase.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assume
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EncSQLiteStatementTypeTest {
    private companion object {
        const val SQLITE_DATA_INTEGER = 1
        const val SQLITE_DATA_FLOAT = 2
        const val SQLITE_DATA_TEXT = 3
        const val SQLITE_DATA_BLOB = 4
        const val SQLITE_DATA_NULL = 5
    }

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Test
    fun getColumnTypeReportsSQLiteDataKinds() {
        val databaseName = "encsqlite-column-types.db"
        val keyMaterial = EncSQLiteKeyMaterial.raw32(ByteArray(32) { 0x5A })

        try {
            val db = EncSQLiteDatabase.open(context, databaseName, keyMaterial)
            try {
                val statement = db.sqliteConnection.prepare(
                    "select 1 as i, 1.5 as r, 'x' as t, x'01' as b, null as n"
                )
                try {
                    assertTrue(statement.step())
                    assertEquals(SQLITE_DATA_INTEGER, statement.getColumnType(0))
                    assertEquals(SQLITE_DATA_FLOAT, statement.getColumnType(1))
                    assertEquals(SQLITE_DATA_TEXT, statement.getColumnType(2))
                    assertEquals(SQLITE_DATA_BLOB, statement.getColumnType(3))
                    assertEquals(SQLITE_DATA_NULL, statement.getColumnType(4))
                } finally {
                    statement.close()
                }
            } finally {
                db.close()
            }
        } catch (error: UnsatisfiedLinkError) {
            Assume.assumeNoException("native bridge is unavailable in this build", error)
        } finally {
            keyMaterial.close()
        }
    }
}
