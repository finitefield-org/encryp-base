# モバイル実機検証手順

`encryp-base` の iOS / Android ラッパーについて、実機または実機相当の状態で確認する項目をまとめます。

この文書の目的は、`T-06` / `T-07` / `T-11` に残る端末依存の確認を、手順として再現可能にすることです。

## 前提

- ルートで C コアをビルド済みであること
- iOS は `cd wrappers/ios && swift test` が通ること
- Android は `cd wrappers/android && gradle assembleDebug` と `gradle connectedDebugAndroidTest` を実行できる環境があること
- Android の実機確認では、端末に画面ロックが設定されていること
- 検証対象の DB はアプリ private storage のみを使うこと
- Android の実機確認を自動化する場合は [scripts/verify_android_device.sh](../scripts/verify_android_device.sh) を使う
- pre-unlock の確認には direct-boot aware receiver と device-protected storage を使う

## iOS

### 1. unlock / lock 切り替え時の open 動作

確認対象:

- `EncSQLiteProtectedDataState.isAvailable`
- `EncSQLiteProtectedDataState.waitUntilAvailable(timeout:)`
- `EncSQLiteDatabase.open(fileURL:keychainItem:options:waitForProtectedDataTimeout:protectedDataWait:)`
- `EncSQLiteOpenOptions.fileProtection`

手順:

1. 端末にパスコードを設定する
2. `EncSQLiteOpenOptions.fileProtection` を `.complete` のままにする
3. DB を open して close する
4. 端末を lock する
5. protected data を待たない open が失敗する、または待機が必要になることを確認する
6. 端末を unlock する
7. 同じ DB が open できることを確認する

期待結果:

- lock 中は protected data が利用不可になる
- unlock 後は open が成功する
- file protection は `.complete` が既定として維持される

### 2. 再インストールと端末移行

確認対象:

- `EncSQLiteKeychainItem`
- `EncSQLiteKeychainItem` の accessibility が `whenUnlockedThisDeviceOnly` であること

手順:

1. DB 用の Keychain item を保存する
2. アプリを再インストールする
3. 同じ bundle id / access group で item を再取得する
4. 別端末へ移行したケースを別途確認する

期待結果:

- 同一端末での再インストール後に item が読めること
- 端末移行後は `ThisDeviceOnly` のため item が引き継がれないこと

## Android

### 1. reboot 後 / unlock 前後の動作

確認対象:

- `EncSQLiteUserUnlockState.isAvailable(context)`
- `EncSQLiteUserUnlockState.waitUntilAvailable(context, timeoutMillis)`
- `EncSQLiteKeyStore.loadOrCreateKeyMaterial(...)`
- `EncSQLiteDatabase.open(context, databaseName, keyStore, ...)`
- `Context.getDatabasePath(...)`
- `Context.getFileStreamPath(...)`
- `EncSQLiteDirectBootHarness`
- `EncSQLiteDirectBootReceiver`

手順:

1. 端末に画面ロックを設定する
2. `gradle connectedDebugAndroidTest` を実行できる状態までアプリとテスト APK を入れる
3. 端末を reboot する
4. unlock 前に `adb shell cmd user is-user-unlocked 0` を確認する
5. unlock 前は `EncSQLiteUserUnlockState.isAvailable(context)` 相当の状態が false であることを確認する
6. unlock 後に `EncSQLiteKeyStore.loadOrCreateKeyMaterial(waitForUserUnlockTimeoutMillis: ...)` が成功することを確認する
7. `EncSQLiteDatabase.databaseFile(context, databaseName)` が app private internal storage 配下を返すことを確認する
8. `Context.getFileStreamPath(...)` に wrapped DEK blob が保存されることを確認する
9. direct-boot aware receiver が device-protected storage に marker を書けることを確認する

期待結果:

- reboot 後、unlock 前は app private internal storage を前提にした処理を遅延できる
- unlock 後は KeyStore / internal storage が利用可能になる
- wrapped DEK blob と DB ファイルの配置先が app private storage である
- device-protected storage には pre-unlock 用の marker を残せる

### 2. instrumentation tests

確認対象:

- `EncSQLiteAndroidStorageTest`
- `EncSQLiteUserUnlockStateTest`

手順:

1. device または emulator を unlock した状態で `gradle connectedDebugAndroidTest` を実行する
2. `EncSQLiteAndroidStorageTest` が internal storage と wrapped blob を確認する
3. `EncSQLiteUserUnlockStateTest` が current availability と wait helper を確認する
4. `EncSQLiteDirectBootHarnessTest` が device-protected storage と receiver を確認する
5. `scripts/verify_android_device.sh` を使う場合は、device が boot 完了して unlock されるまで待機してから同じ connected test を実行する

期待結果:

- unlocked 状態で internal storage と KeyStore-backed blob の永続化が確認できる
- `waitUntilAvailable(context, 0L)` が現在の user-unlocked 状態と一致する
- direct-boot harness は device-protected storage に marker を残せる

## 補足

- 標準の instrumentation tests は unlock 後の実行を前提にしている
- unlock 前の実行を自動化したい場合は、direct boot aware の検証ハーネスを別途追加する
- この文書は、実機確認の前提と期待値を固定するためのもので、端末実行そのものは含まない
