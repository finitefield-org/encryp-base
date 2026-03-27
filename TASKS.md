# Tasks

`encryp-base` の実装タスク一覧です。各項目は、1 作業単位で進めやすい粒度にしています。

## T-01 実装基盤の固定

- [x] SQLite の採用バージョンと取り込み方法を決める
- [x] C API / core source / wrapper のディレクトリ構成を決める
- [x] debug / release のビルド設定を追加する
- [x] ローカルで再現できるコマンドを README に追記する

## T-02 暗号プリミティブ実装

- [x] AES-256-GCM のラッパーを実装する
- [x] HKDF-SHA-256 のラッパーを実装する
- [x] Argon2id のラッパーを実装する
- [x] OS CSPRNG と zeroize ヘルパーを実装する
- [x] known-answer test を追加する

## T-03 ページ形式の確定

- [x] `page_size = 4096` と `reserve_size = 36` を定数化する
- [x] page 1 / page > 1 のレイアウトを実装する
- [x] `db_salt` / `nonce` / `tag` / `key_epoch` の配置を確定する
- [x] AAD 生成ロジックを実装する
- [x] 形式検証テストを追加する

## T-04 codec 実装

- [x] page > 1 の read path を実装する
- [x] page > 1 の write path を実装する
- [x] page 1 のヘッダ合成と検証を実装する
- [x] tag failure のエラー正規化を実装する
- [x] page swap / bit flip の破壊テストを追加する

## T-05 SQLite 統合

- [x] SQLite 接続ラッパーを追加する
- [x] pager 初期化に codec context を差し込む
- [x] WAL / rollback journal の経路を接続する
- [x] authorizer と固定 PRAGMA を導入する
- [x] `mmap_size = 0` と `load_extension()` 無効化を固定する
- [x] 基本 SQL 操作の結合テストを追加する

## T-06 鍵保護 iOS

- [x] Keychain 保存 / 取得 / 削除のヘルパーを実装する
- [x] `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` を既定にする
- [x] DB ファイルの File Protection 設定を実装する
- [x] Keychain item から直接 open する helper を追加する
- [x] protected data available を待つ helper を追加する
- [ ] unlock / lock 切り替え時の open 動作を確認する
- [ ] 再インストールと端末移行の挙動を検証する

## T-07 鍵保護 Android

- [x] Keystore wrapping key を生成する
- [x] DEK の wrap / unwrap を実装する
- [x] wrapped blob の保存先を internal storage に固定する
- [x] StrongBox 優先生成を実装する
- [x] user-unlocked 待ち helper を追加する
- [ ] reboot 後 / unlock 前後の動作を検証する

## T-08 公開 API 実装

- [x] C ヘッダに公開型と error code を定義する
- [x] `encsqlite_open_v2()` を実装する
- [x] `encsqlite_migrate_plaintext()` を実装する
- [x] `encsqlite_rekey_copy_swap()` を実装する
- [x] `encsqlite_export()` / `encsqlite_checkpoint()` / `encsqlite_close_secure()` を実装する

## T-09 migrate / rekey 実装

- [x] source DB を read-only で開く
- [x] backup API で `dest.tmp` にコピーする
- [x] quick_check と `application_id` 検証を実装する
- [x] fsync と atomic rename を実装する
- [x] recovery marker の作成 / 読み出し / 復旧を実装する
- [x] bak 削除の遅延回収を実装する

## T-10 wrapper 実装

- [x] Swift wrapper の open API を実装する
- [x] JNI binding を実装する
- [x] Room 用 factory を実装する
- [x] サンプルアプリまたは最小利用例を追加する
- [x] wrapper の使用例をドキュメント化する

## T-11 テスト拡充

- [x] differential test を追加する
- [x] page 1 / page N の破損テストを追加する
- [x] stale WAL の差し戻しテストを追加する
- [x] power loss / kill / rename 途中中断のテストを追加する
- [x] benchmark を追加する
- [x] iOS の file protection class を検証する
- [x] Android の internal storage open API を追加する
- [x] Android の instrumentation test スケルトンを追加する
- [x] Android の instrumentation test をエミュレータで実行する
- [x] iOS / Android の実機検証手順を文書化する
- [x] Android の実機検証用スクリプトを追加する
- [x] Android の direct-boot harness を追加する
- [ ] Android の file protection / internal storage を実機で検証する
- [x] 禁止 PRAGMA とログ露出の検証を追加する

## T-12 運用設計

- [x] ログ出力ポリシーを定義する
- [x] バックアップ / 復元ポリシーを定義する
- [x] 端末移行ポリシーを定義する
- [x] 非対応機能の一覧を整理する
- [x] リリース前チェックリストを作成する
- [x] 運用向け README を整備する

## 優先順

1. T-01 から T-04 で暗号フォーマットと codec を固める
2. T-05 から T-08 で SQLite 統合と API を固める
3. T-09 と T-10 で運用可能な形にまとめる
4. T-11 と T-12 で品質と導入情報を整える

## 参照

- [README](README.md)
- [ROADMAP](ROADMAP.md)
- [SQLite 暗号化パッケージ設計書](doc/sqlite_encryption_package_design.md)
