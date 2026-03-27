@file:Suppress("AcronymName")

package io.github.kazuyoshitoshiya.encrypbase.android

import androidx.room.RoomDatabase
import android.content.Context
import androidx.sqlite.SQLiteConnection
import androidx.sqlite.SQLiteDriver
import androidx.sqlite.SQLiteStatement
import androidx.sqlite.throwSQLiteException
import java.io.Closeable
import java.io.File

private const val SQLITE_OK = 0
private const val SQLITE_ROW = 100
private const val SQLITE_DONE = 101
private const val SQLITE_MISUSE = 21
private const val SQLITE_RANGE = 25
private const val SQLITE_READONLY = 8

public data class EncSQLiteOpenOptions(
    val createIfMissing: Boolean = true,
    val readOnly: Boolean = false,
    val expectApplicationId: Boolean = false,
    val applicationId: Int = 0,
    val journalModeWal: Boolean = true,
)

public class EncSQLiteKeyMaterial private constructor(private var bytes: ByteArray) : Closeable {
    public companion object {
        @JvmStatic
        public fun raw32(bytes: ByteArray): EncSQLiteKeyMaterial {
            require(bytes.size == 32) {
                "EncSQLiteKeyMaterial requires exactly 32 bytes"
            }
            return EncSQLiteKeyMaterial(bytes.copyOf())
        }
    }

    private var closed = false

    internal fun copyBytes(): ByteArray {
        check(!closed) { "EncSQLiteKeyMaterial is closed" }
        return bytes.copyOf()
    }

    public fun contentEquals(other: EncSQLiteKeyMaterial): Boolean {
        check(!closed) { "EncSQLiteKeyMaterial is closed" }
        check(!other.closed) { "EncSQLiteKeyMaterial is closed" }
        return bytes.contentEquals(other.bytes)
    }

    override fun close() {
        if (closed) {
            return
        }
        bytes.fill(0)
        closed = true
    }
}

public class EncSQLiteDatabase private constructor(
    private val connection: EncSQLiteConnection
) : Closeable {
    public val sqliteConnection: SQLiteConnection
        get() = connection

    public fun checkpoint(truncate: Boolean = false) {
        connection.checkpoint(truncate)
    }

    override fun close() {
        connection.close()
    }

    public companion object {
        @JvmStatic
        public fun databaseFile(
            context: Context,
            databaseName: String
        ): File {
            require(databaseName.isNotBlank()) { "Database name must not be blank" }
            require(!databaseName.contains('/')) { "Database name must not contain path separators" }
            require(!databaseName.contains('\\')) { "Database name must not contain path separators" }
            return context.getDatabasePath(databaseName)
        }

        @JvmStatic
        public fun open(
            path: String,
            keyMaterial: EncSQLiteKeyMaterial,
            options: EncSQLiteOpenOptions = EncSQLiteOpenOptions()
        ): EncSQLiteDatabase {
            val driver = EncSQLiteDriver(keyMaterial, options)
            return EncSQLiteDatabase(driver.open(path) as EncSQLiteConnection)
        }

        @JvmStatic
        public fun open(
            context: Context,
            databaseName: String,
            keyMaterial: EncSQLiteKeyMaterial,
            options: EncSQLiteOpenOptions = EncSQLiteOpenOptions()
        ): EncSQLiteDatabase {
            return open(databaseFile(context, databaseName), keyMaterial, options)
        }

        @JvmStatic
        public fun open(
            context: Context,
            databaseName: String,
            keyStore: EncSQLiteKeyStore,
            options: EncSQLiteOpenOptions = EncSQLiteOpenOptions(),
            waitForUserUnlockTimeoutMillis: Long = 0L,
            userUnlockWait: ((Context, Long) -> Boolean)? = null
        ): EncSQLiteDatabase {
            val keyMaterial = keyStore.loadOrCreateKeyMaterial(
                waitForUserUnlockTimeoutMillis,
                userUnlockWait
            )
            try {
                return open(context, databaseName, keyMaterial, options)
            } finally {
                keyMaterial.close()
            }
        }

        @JvmStatic
        public fun open(
            file: File,
            keyMaterial: EncSQLiteKeyMaterial,
            options: EncSQLiteOpenOptions = EncSQLiteOpenOptions()
        ): EncSQLiteDatabase {
            return open(file.absolutePath, keyMaterial, options)
        }
    }
}

public class EncSQLiteDriver(
    private val keyMaterial: EncSQLiteKeyMaterial,
    private val options: EncSQLiteOpenOptions = EncSQLiteOpenOptions()
) : SQLiteDriver {
    override val hasConnectionPool: Boolean
        get() = false

    override fun open(fileName: String): SQLiteConnection {
        require(fileName.isNotBlank()) { "Database path must not be blank" }
        require(fileName != ":memory:") {
            "EncSQLiteDriver does not support in-memory databases"
        }
        require(!fileName.startsWith("file:", ignoreCase = true)) {
            "EncSQLiteDriver does not support URI filenames"
        }

        val keyBytes = keyMaterial.copyBytes()
        return try {
            val handle = EncSQLiteNative.nativeOpenConnection(
                fileName,
                keyBytes,
                options.createIfMissing,
                options.readOnly,
                options.expectApplicationId,
                options.applicationId,
                options.journalModeWal
            )
            check(handle != 0L) {
                "nativeOpenConnection returned an invalid handle"
            }
            EncSQLiteConnection(handle, options)
        } finally {
            keyBytes.fill(0)
        }
    }
}

public class EncSQLiteRoomFactory(
    keyMaterial: EncSQLiteKeyMaterial,
    options: EncSQLiteOpenOptions = EncSQLiteOpenOptions()
) {
    public val driver: SQLiteDriver = EncSQLiteDriver(keyMaterial, options)

    public fun <T : RoomDatabase> configure(
        builder: RoomDatabase.Builder<T>
    ): RoomDatabase.Builder<T> {
        return builder.setDriver(driver)
    }
}

internal class EncSQLiteConnection(
    private var handle: Long,
    private val options: EncSQLiteOpenOptions
) : SQLiteConnection {
    private var closed = false

    override fun prepare(sql: String): SQLiteStatement {
        checkOpen()
        val statementHandle = EncSQLiteNative.nativePrepareStatement(handle, sql)
        check(statementHandle != 0L) {
            "nativePrepareStatement returned an invalid handle"
        }
        return EncSQLiteStatement(statementHandle)
    }

    override fun inTransaction(): Boolean {
        checkOpen()
        return EncSQLiteNative.nativeConnectionInTransaction(handle)
    }

    internal fun checkpoint(truncate: Boolean) {
        checkOpen()
        if (options.readOnly) {
            throwSQLiteException(
                SQLITE_READONLY,
                "checkpoint is not available on a read-only connection"
            )
        }
        val rc = EncSQLiteNative.nativeCheckpointConnection(handle, truncate)
        if (rc != SQLITE_OK) {
            throwSQLiteException(rc, "checkpoint failed")
        }
    }

    override fun close() {
        if (closed) {
            return
        }

        val rc = EncSQLiteNative.nativeCloseConnection(handle)
        if (rc == SQLITE_OK) {
            handle = 0L
            closed = true
            return
        }

        throwSQLiteException(rc, "close failed")
    }

    private fun checkOpen() {
        if (closed || handle == 0L) {
            throwSQLiteException(SQLITE_MISUSE, "connection is closed")
        }
    }
}

internal class EncSQLiteStatement(
    private var handle: Long
) : SQLiteStatement {
    private var closed = false
    private var hasCurrentRow = false

    override fun bindBlob(index: Int, value: ByteArray) {
        checkOpen()
        checkResult(EncSQLiteNative.nativeBindBlob(handle, index, value), "bindBlob")
        hasCurrentRow = false
    }

    override fun bindLong(index: Int, value: Long) {
        checkOpen()
        checkResult(EncSQLiteNative.nativeBindLong(handle, index, value), "bindLong")
        hasCurrentRow = false
    }

    override fun bindDouble(index: Int, value: Double) {
        checkOpen()
        checkResult(EncSQLiteNative.nativeBindDouble(handle, index, value), "bindDouble")
        hasCurrentRow = false
    }

    override fun bindText(index: Int, value: String) {
        checkOpen()
        checkResult(EncSQLiteNative.nativeBindText(handle, index, value), "bindText")
        hasCurrentRow = false
    }

    override fun bindNull(index: Int) {
        checkOpen()
        checkResult(EncSQLiteNative.nativeBindNull(handle, index), "bindNull")
        hasCurrentRow = false
    }

    override fun getText(index: Int): String {
        checkRow()
        checkColumnIndex(index)
        return EncSQLiteNative.nativeGetColumnText(handle, index)
    }

    override fun getLong(index: Int): Long {
        checkRow()
        checkColumnIndex(index)
        return EncSQLiteNative.nativeGetColumnLong(handle, index)
    }

    override fun getBlob(index: Int): ByteArray {
        checkRow()
        checkColumnIndex(index)
        return EncSQLiteNative.nativeGetColumnBlob(handle, index)
    }

    override fun getDouble(index: Int): Double {
        checkRow()
        checkColumnIndex(index)
        return EncSQLiteNative.nativeGetColumnDouble(handle, index)
    }

    override fun isNull(index: Int): Boolean {
        checkRow()
        checkColumnIndex(index)
        return EncSQLiteNative.nativeIsColumnNull(handle, index)
    }

    override fun getColumnCount(): Int {
        checkOpen()
        return EncSQLiteNative.nativeGetColumnCount(handle)
    }

    override fun getColumnName(index: Int): String {
        checkOpen()
        checkColumnIndex(index)
        return EncSQLiteNative.nativeGetColumnName(handle, index)
    }

    override fun getColumnType(index: Int): Int {
        checkRow()
        checkColumnIndex(index)
        return EncSQLiteNative.nativeGetColumnType(handle, index)
    }

    override fun step(): Boolean {
        checkOpen()
        val rc = EncSQLiteNative.nativeStepStatement(handle)
        return when (rc) {
            SQLITE_ROW -> {
                hasCurrentRow = true
                true
            }
            SQLITE_DONE -> {
                hasCurrentRow = false
                false
            }
            else -> {
                hasCurrentRow = false
                throwSQLiteException(rc, "step failed")
            }
        }
    }

    override fun reset() {
        checkOpen()
        checkResult(EncSQLiteNative.nativeResetStatement(handle), "reset")
        hasCurrentRow = false
    }

    override fun clearBindings() {
        checkOpen()
        checkResult(EncSQLiteNative.nativeClearBindings(handle), "clearBindings")
        hasCurrentRow = false
    }

    override fun close() {
        if (closed) {
            return
        }

        val rc = EncSQLiteNative.nativeFinalizeStatement(handle)
        handle = 0L
        closed = true
        hasCurrentRow = false
        if (rc != SQLITE_OK) {
            throwSQLiteException(rc, "finalize failed")
        }
    }

    private fun checkResult(rc: Int, operation: String) {
        if (rc != SQLITE_OK) {
            throwSQLiteException(rc, "$operation failed")
        }
    }

    private fun checkOpen() {
        if (closed || handle == 0L) {
            throwSQLiteException(SQLITE_MISUSE, "statement is closed")
        }
    }

    private fun checkRow() {
        checkOpen()
        if (!hasCurrentRow) {
            throwSQLiteException(SQLITE_MISUSE, "statement has no current row")
        }
    }

    private fun checkColumnIndex(index: Int) {
        val columnCount = EncSQLiteNative.nativeGetColumnCount(handle)
        if (index < 0 || index >= columnCount) {
            throwSQLiteException(SQLITE_RANGE, "column index out of range")
        }
    }
}

internal object EncSQLiteNative {
    init {
        System.loadLibrary("encsqlite_android_jni")
    }

    external fun nativeOpenConnection(
        fileName: String,
        keyBytes: ByteArray,
        createIfMissing: Boolean,
        readOnly: Boolean,
        expectApplicationId: Boolean,
        applicationId: Int,
        journalModeWal: Boolean
    ): Long

    external fun nativeCloseConnection(connectionHandle: Long): Int

    external fun nativeConnectionInTransaction(connectionHandle: Long): Boolean

    external fun nativeCheckpointConnection(connectionHandle: Long, truncate: Boolean): Int

    external fun nativePrepareStatement(connectionHandle: Long, sql: String): Long

    external fun nativeFinalizeStatement(statementHandle: Long): Int

    external fun nativeBindBlob(statementHandle: Long, index: Int, value: ByteArray): Int

    external fun nativeBindLong(statementHandle: Long, index: Int, value: Long): Int

    external fun nativeBindDouble(statementHandle: Long, index: Int, value: Double): Int

    external fun nativeBindText(statementHandle: Long, index: Int, value: String): Int

    external fun nativeBindNull(statementHandle: Long, index: Int): Int

    external fun nativeClearBindings(statementHandle: Long): Int

    external fun nativeResetStatement(statementHandle: Long): Int

    external fun nativeStepStatement(statementHandle: Long): Int

    external fun nativeGetColumnCount(statementHandle: Long): Int

    external fun nativeGetColumnName(statementHandle: Long, index: Int): String

    external fun nativeGetColumnType(statementHandle: Long, index: Int): Int

    external fun nativeIsColumnNull(statementHandle: Long, index: Int): Boolean

    external fun nativeGetColumnLong(statementHandle: Long, index: Int): Long

    external fun nativeGetColumnDouble(statementHandle: Long, index: Int): Double

    external fun nativeGetColumnText(statementHandle: Long, index: Int): String

    external fun nativeGetColumnBlob(statementHandle: Long, index: Int): ByteArray
}
