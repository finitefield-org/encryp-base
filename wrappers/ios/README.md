# EncSQLite iOS Wrapper

`wrappers/ios` は、`encryp-base` の C API を Swift から扱うための SwiftPM パッケージです。

## 前提

- 先にルートで `cmake --build build --parallel` を実行しておく
- Swift 6.0 以上
- iOS / macOS SDK が使える Xcode / Swift toolchain

## Build

```bash
cd wrappers/ios
swift test
```

## 使い方

```swift
import Foundation
import EncSQLite

let key = try EncSQLiteKeyMaterial(raw32: Array(repeating: 0x11, count: 32))
let options = EncSQLiteOpenOptions(expectApplicationID: true, applicationID: 0x454E4353)
let db = try EncSQLiteDatabase.open(
    fileURL: URL(fileURLWithPath: "/path/to/database.sqlite"),
    key: key,
    options: options
)

try db.checkpoint(truncate: false)
try db.close()
```

Keychain の generic password item を扱うときは `EncSQLiteKeychainItem` を使います。既定の accessibility は `whenUnlockedThisDeviceOnly` です。

```swift
let keychain = try EncSQLiteKeychainItem(
    service: "com.example.encryp-base",
    account: "database-dek"
)
try keychain.save(Data(repeating: 0x11, count: 32))
let stored = try keychain.load()
try keychain.delete()
```

保存済みの Keychain item から直接 DB を開くには `EncSQLiteDatabase.open(fileURL:keychainItem:options:)` を使います。

iOS の protected data が利用可能になるまで待つには `EncSQLiteProtectedDataState.waitUntilAvailable(timeout:)` を使います。
protected data を待ってから開く場合は `EncSQLiteDatabase.open(fileURL:keychainItem:options:waitForProtectedDataTimeout:protectedDataWait:)` を使います。

`EncSQLiteOpenOptions.fileProtection` の既定値は `.complete` です。バックグラウンド復帰が必要な場合だけ `.completeUntilFirstUserAuthentication` に下げます。

現時点で提供しているのは `open` / `checkpoint` / `close`、Keychain helper、protected data helper の最小 API です。Android 側の JNI / Room wrapper は別タスクで実装します。

実機検証の手順は [doc/mobile_device_verification.md](../../doc/mobile_device_verification.md) にまとめています。
