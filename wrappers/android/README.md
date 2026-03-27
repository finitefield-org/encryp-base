# EncSQLite Android Wrapper

`wrappers/android` contains the JNI and Room-facing wrapper sources for the Android side of `encryp-base`.

## Prerequisites

- Android Gradle Plugin 9.1.0 and Gradle 9.3.1
- AndroidX Room 2.8.4 with `RoomDatabase.Builder.setDriver(...)`
- `androidx.sqlite:sqlite` 2.6.2
- AndroidX Test for instrumentation tests
- Android SDK API 23+
- Android NDK / CMake integration for the native bridge when you wire the C layer in
- Built-in Kotlin support from AGP 9.x

## Public API

- `EncSQLiteKeyMaterial`: raw 32-byte key material helper
- `EncSQLiteKeyStore`: Android Keystore wrapping key and wrapped DEK blob helper
- `EncSQLiteUserUnlockState`: helper for waiting on user-unlocked state after reboot
- `EncSQLiteDirectBootHarness`: helper for device-protected pre-unlock marker storage
- `EncSQLiteOpenOptions`: open-time policy flags
- `EncSQLiteDatabase`: direct open / checkpoint / close helper
- `EncSQLiteDriver`: `androidx.sqlite.SQLiteDriver` implementation
- `EncSQLiteRoomFactory`: helper for `RoomDatabase.Builder.setDriver(...)`

## Build

The wrapper now includes a minimal Gradle library scaffold.

```bash
cd wrappers/android
gradle assembleDebug
```

To opt into the native bridge wiring, pass:

```bash
gradle assembleDebug -Pencsqlite.buildNativeBridge=true
```

That path still expects Android-compatible crypto backends to be available for the JNI target. The shared library name remains `encsqlite_android_jni`.

## Instrumented Tests

The module also includes Android instrumentation tests for internal storage path resolution and Keystore-backed blob persistence.

```bash
cd wrappers/android
gradle connectedDebugAndroidTest
```

`EncSQLiteUserUnlockState.waitUntilAvailable(...)` is available for apps that need to defer file-backed operations until the user has unlocked the device after reboot.

`EncSQLiteKeyStore.loadOrCreateKeyMaterial(...)` also accepts an optional unlock wait callback and timeout so callers can delay internal storage access until the device is ready.

`EncSQLiteDirectBootHarness` writes a small marker file into device-protected storage from a direct-boot aware receiver so pre-unlock behavior can be verified after the device comes back up.

The manual device verification checklist is documented in [doc/mobile_device_verification.md](../../doc/mobile_device_verification.md).

For a repeatable device verification flow, use [scripts/verify_android_device.sh](../../scripts/verify_android_device.sh).

## Usage

### Direct open

```kotlin
val key = EncSQLiteKeyMaterial.raw32(ByteArray(32) { 0x11.toByte() })
val db = EncSQLiteDatabase.open(context, "app.encsqlite", key)

try {
    db.checkpoint(truncate = false)
} finally {
    db.close()
    key.close()
}
```

### Keystore-backed open

```kotlin
val keyStore = EncSQLiteKeyStore(context)
val db = EncSQLiteDatabase.open(context, "app.encsqlite", keyStore)

try {
    db.checkpoint(truncate = false)
} finally {
    db.close()
}
```

### Room integration

```kotlin
val key = EncSQLiteKeyMaterial.raw32(ByteArray(32) { 0x11.toByte() })
val factory = EncSQLiteRoomFactory(key)

val roomDb = factory.configure(
    Room.databaseBuilder(context, AppDatabase::class.java, "app.encsqlite")
).build()
```

## Native bridge

The JNI entry points live in `src/main/cpp/encsqlite_jni.c` and expect the Android module to compile the existing C core together with the SQLite amalgamation and its crypto backends.

- The Kotlin loader expects a shared library named `encsqlite_android_jni`

## Notes

- The wrapper currently targets file-backed databases only.
- In-memory and URI filenames are rejected by the Kotlin wrapper.
- Direct open through `Context` resolves the database path inside app-private internal storage.
- Wrapped DEK blobs are stored in app-private internal storage via `Context.openFileOutput(...)`.
- The Keystore helper can wait for the user-unlocked state before reading or writing app-private files.
- The repository now ships a minimal Android Gradle module scaffold; the JNI target is opt-in and still depends on Android-compatible crypto backends.
