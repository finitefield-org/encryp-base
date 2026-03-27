@file:Suppress("AcronymName")

package io.github.kazuyoshitoshiya.encrypbase.android

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.FileNotFoundException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val ENCSQLITE_ANDROID_KEY_SIZE_BITS = 256
private const val ENCSQLITE_ANDROID_KEY_MATERIAL_BYTES = 32
private const val ENCSQLITE_ANDROID_GCM_TAG_SIZE_BITS = 128
private const val ENCSQLITE_ANDROID_GCM_IV_BYTES = 12
private const val ENCSQLITE_ANDROID_BLOB_VERSION: Byte = 1

public data class EncSQLiteKeyStoreOptions(
    val wrappingKeyAlias: String = "encsqlite_android_wrapping_key",
    val wrappedKeyFileName: String = "encsqlite_wrapped_dek.bin",
    val strongBoxPreferred: Boolean = true,
)

public class EncSQLiteKeyStore(
    context: Context,
    private val options: EncSQLiteKeyStoreOptions = EncSQLiteKeyStoreOptions()
) {
    private val appContext: Context = context.applicationContext

    private fun waitForUserUnlock(
        timeoutMillis: Long,
        userUnlockWait: ((Context, Long) -> Boolean)?
    ): Boolean {
        if (timeoutMillis <= 0L && userUnlockWait == null) {
            return true
        }
        val waitFunction = userUnlockWait ?: EncSQLiteUserUnlockState::waitUntilAvailable
        return waitFunction(appContext, timeoutMillis)
    }

    public fun saveKeyMaterial(
        keyMaterial: EncSQLiteKeyMaterial,
        waitForUserUnlockTimeoutMillis: Long = 0L,
        userUnlockWait: ((Context, Long) -> Boolean)? = null
    ) {
        if (!waitForUserUnlock(waitForUserUnlockTimeoutMillis, userUnlockWait)) {
            throw IllegalStateException("user unlock is unavailable")
        }
        val wrappedBlob = wrapWithoutWait(keyMaterial)
        try {
            writeWrappedBlob(wrappedBlob)
        } finally {
            wrappedBlob.fill(0)
        }
    }

    public fun loadKeyMaterial(
        waitForUserUnlockTimeoutMillis: Long = 0L,
        userUnlockWait: ((Context, Long) -> Boolean)? = null
    ): EncSQLiteKeyMaterial? {
        if (!waitForUserUnlock(waitForUserUnlockTimeoutMillis, userUnlockWait)) {
            throw IllegalStateException("user unlock is unavailable")
        }
        return loadKeyMaterialWithoutWait()
    }

    public fun loadOrCreateKeyMaterial(
        waitForUserUnlockTimeoutMillis: Long = 0L,
        userUnlockWait: ((Context, Long) -> Boolean)? = null
    ): EncSQLiteKeyMaterial {
        if (!waitForUserUnlock(waitForUserUnlockTimeoutMillis, userUnlockWait)) {
            throw IllegalStateException("user unlock is unavailable")
        }

        val existing = loadKeyMaterialWithoutWait()
        if (existing != null) {
            return existing
        }

        val seed = ByteArray(ENCSQLITE_ANDROID_KEY_MATERIAL_BYTES)
        SecureRandom().nextBytes(seed)
        try {
            val keyMaterial = EncSQLiteKeyMaterial.raw32(seed)
            saveKeyMaterialWithoutWait(keyMaterial)
            return keyMaterial
        } finally {
            seed.fill(0)
        }
    }

    public fun deleteKeyMaterial(
        waitForUserUnlockTimeoutMillis: Long = 0L,
        userUnlockWait: ((Context, Long) -> Boolean)? = null
    ) {
        if (!waitForUserUnlock(waitForUserUnlockTimeoutMillis, userUnlockWait)) {
            throw IllegalStateException("user unlock is unavailable")
        }
        appContext.deleteFile(options.wrappedKeyFileName)
    }

    public fun wrap(
        keyMaterial: EncSQLiteKeyMaterial,
        waitForUserUnlockTimeoutMillis: Long = 0L,
        userUnlockWait: ((Context, Long) -> Boolean)? = null
    ): ByteArray {
        if (!waitForUserUnlock(waitForUserUnlockTimeoutMillis, userUnlockWait)) {
            throw IllegalStateException("user unlock is unavailable")
        }
        return wrapWithoutWait(keyMaterial)
    }

    public fun unwrap(
        wrappedBlob: ByteArray,
        waitForUserUnlockTimeoutMillis: Long = 0L,
        userUnlockWait: ((Context, Long) -> Boolean)? = null
    ): EncSQLiteKeyMaterial {
        if (!waitForUserUnlock(waitForUserUnlockTimeoutMillis, userUnlockWait)) {
            throw IllegalStateException("user unlock is unavailable")
        }
        return unwrapWithoutWait(wrappedBlob)
    }

    public fun hasStoredKeyMaterial(): Boolean {
        return appContext.getFileStreamPath(options.wrappedKeyFileName).exists()
    }

    private fun getOrCreateWrappingKey(): SecretKey {
        loadAndroidKeyStore().getKey(options.wrappingKeyAlias, null)?.let { key ->
            return key as SecretKey
        }
        return generateWrappingKey(options.strongBoxPreferred)
    }

    private fun loadExistingWrappingKey(): SecretKey {
        val key = loadAndroidKeyStore().getKey(options.wrappingKeyAlias, null)
        return key as? SecretKey
            ?: throw IllegalStateException("Android Keystore wrapping key is missing")
    }

    private fun generateWrappingKey(preferStrongBox: Boolean): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )
        val builder = KeyGenParameterSpec.Builder(
            options.wrappingKeyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(ENCSQLITE_ANDROID_KEY_SIZE_BITS)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && preferStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        return try {
            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        } catch (error: Exception) {
            if (preferStrongBox) {
                return generateWrappingKey(false)
            }
            throw IllegalStateException("failed to generate Android Keystore wrapping key", error)
        }
    }

    private fun loadAndroidKeyStore(): KeyStore {
        return try {
            KeyStore.getInstance("AndroidKeyStore").apply {
                load(null, null)
            }
        } catch (error: Exception) {
            throw IllegalStateException("failed to load Android Keystore", error)
        }
    }

    private fun encryptKeyBytes(secretKey: SecretKey, rawKey: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv ?: throw IllegalStateException("AES/GCM cipher did not produce an IV")
        if (iv.size != ENCSQLITE_ANDROID_GCM_IV_BYTES) {
            throw IllegalStateException("unexpected AES/GCM IV length")
        }

        val ciphertext = cipher.doFinal(rawKey)
        val blob = ByteArray(2 + iv.size + ciphertext.size)
        blob[0] = ENCSQLITE_ANDROID_BLOB_VERSION
        blob[1] = iv.size.toByte()
        System.arraycopy(iv, 0, blob, 2, iv.size)
        System.arraycopy(ciphertext, 0, blob, 2 + iv.size, ciphertext.size)
        return blob
    }

    private fun decryptKeyBytes(wrappedBlob: ByteArray): ByteArray {
        if (wrappedBlob.size < 2) {
            throw IllegalStateException("wrapped key blob is too short")
        }
        if (wrappedBlob[0] != ENCSQLITE_ANDROID_BLOB_VERSION) {
            throw IllegalStateException("unsupported wrapped key blob version")
        }

        val ivLength = wrappedBlob[1].toInt() and 0xFF
        if (ivLength != ENCSQLITE_ANDROID_GCM_IV_BYTES) {
            throw IllegalStateException("unexpected wrapped key blob IV length")
        }
        if (wrappedBlob.size <= 2 + ivLength) {
            throw IllegalStateException("wrapped key blob is truncated")
        }

        val iv = wrappedBlob.copyOfRange(2, 2 + ivLength)
        val ciphertext = wrappedBlob.copyOfRange(2 + ivLength, wrappedBlob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            loadExistingWrappingKey(),
            GCMParameterSpec(ENCSQLITE_ANDROID_GCM_TAG_SIZE_BITS, iv)
        )
        return cipher.doFinal(ciphertext)
    }

    private fun wrappedBlobFileName(): String {
        require(options.wrappedKeyFileName.isNotBlank()) {
            "wrapped key file name must not be blank"
        }
        return options.wrappedKeyFileName
    }

    private fun saveKeyMaterialWithoutWait(keyMaterial: EncSQLiteKeyMaterial) {
        val wrappedBlob = wrapWithoutWait(keyMaterial)
        try {
            writeWrappedBlob(wrappedBlob)
        } finally {
            wrappedBlob.fill(0)
        }
    }

    private fun loadKeyMaterialWithoutWait(): EncSQLiteKeyMaterial? {
        val wrappedBlob = readWrappedBlob() ?: return null
        try {
            return unwrapWithoutWait(wrappedBlob)
        } finally {
            wrappedBlob.fill(0)
        }
    }

    private fun wrapWithoutWait(keyMaterial: EncSQLiteKeyMaterial): ByteArray {
        val rawKey = keyMaterial.copyBytes()
        try {
            val secretKey = getOrCreateWrappingKey()
            return encryptKeyBytes(secretKey, rawKey)
        } finally {
            rawKey.fill(0)
        }
    }

    private fun unwrapWithoutWait(wrappedBlob: ByteArray): EncSQLiteKeyMaterial {
        val rawKey = decryptKeyBytes(wrappedBlob)
        try {
            return EncSQLiteKeyMaterial.raw32(rawKey)
        } finally {
            rawKey.fill(0)
        }
    }

    private fun writeWrappedBlob(blob: ByteArray) {
        appContext.openFileOutput(wrappedBlobFileName(), Context.MODE_PRIVATE).use { output ->
            output.write(blob)
            output.flush()
        }
    }

    private fun readWrappedBlob(): ByteArray? {
        return try {
            appContext.openFileInput(wrappedBlobFileName()).use { input ->
                input.readBytes()
            }
        } catch (_: FileNotFoundException) {
            null
        }
    }
}
