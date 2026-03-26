# Tasks

`encryp-base` の実装タスク一覧です。各項目は、1 作業単位で進めやすい粒度にしています。

## T-01 実装基盤の固定

- [x] SQLite の採用バージョンと取り込み方法を決める
- [x] C API / core source / wrapper のディレクトリ構成を決める
- [x] debug / release のビルド設定を追加する
- [x] CI で build と unit test を回す
- [x] ローカルで再現できるコマンドを README に追記する

## T-02 暗号プリミティブ実装

- [ ] AES-256-GCM のラッパーを実装する
- [ ] HKDF-SHA-256 のラッパーを実装する
- [ ] Argon2id のラッパーを実装する
- [ ] OS CSPRNG と zeroize ヘルパーを実装する
- [ ] known-answer test を追加する

## T-03 ページ形式の確定

- [ ] `page_size = 4096` と `reserve_size = 36` を定数化する
- [ ] page 1 / page > 1 のレイアウトを実装する
- [ ] `db_salt` / `nonce` / `tag` / `key_epoch` の配置を確定する
- [ ] AAD 生成ロジックを実装する
- [ ] 形式検証テストを追加する

## T-04 codec 実装

- [ ] page > 1 の read path を実装する
- [ ] page > 1 の write path を実装する
- [ ] page 1 のヘッダ合成と検証を実装する
- [ ] tag failure のエラー正規化を実装する
- [ ] page swap / bit flip の破壊テストを追加する

## T-05 SQLite 統合

- [ ] pager 初期化に codec context を差し込む
- [ ] WAL / rollback journal の経路を接続する
- [ ] authorizer と固定 PRAGMA を導入する
- [ ] `mmap_size = 0` と `load_extension()` 無効化を固定する
- [ ] 基本 SQL 操作の結合テストを追加する

## T-06 鍵保護 iOS

- [ ] Keychain 保存 / 取得 / 削除のヘルパーを実装する
- [ ] `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` を既定にする
- [ ] DB ファイルの File Protection 設定を実装する
- [ ] unlock / lock 切り替え時の open 動作を確認する
- [ ] 再インストールと端末移行の挙動を検証する

## T-07 鍵保護 Android

- [ ] Keystore wrapping key を生成する
- [ ] DEK の wrap / unwrap を実装する
- [ ] wrapped blob の保存先を internal storage に固定する
- [ ] StrongBox 優先生成を実装する
- [ ] reboot 後 / unlock 前後の動作を検証する

## T-08 公開 API 実装

- [ ] C ヘッダに公開型と error code を定義する
- [ ] `encsqlite_open_v2()` を実装する
- [ ] `encsqlite_migrate_plaintext()` を実装する
- [ ] `encsqlite_rekey_copy_swap()` を実装する
- [ ] `encsqlite_export()` / `encsqlite_checkpoint()` / `encsqlite_close_secure()` を実装する

## T-09 migrate / rekey 実装

- [ ] source DB を read-only で開く
- [ ] backup API で `dest.tmp` にコピーする
- [ ] quick_check と `application_id` 検証を実装する
- [ ] fsync と atomic rename を実装する
- [ ] recovery marker の作成 / 読み出し / 復旧を実装する
- [ ] bak 削除の遅延回収を実装する

## T-10 wrapper 実装

- [ ] Swift wrapper の open API を実装する
- [ ] JNI binding を実装する
- [ ] Room 用 factory を実装する
- [ ] サンプルアプリまたは最小利用例を追加する
- [ ] wrapper の使用例をドキュメント化する

## T-11 テスト拡充

- [ ] differential test を追加する
- [ ] page 1 / page N の破損テストを追加する
- [ ] stale WAL の差し戻しテストを追加する
- [ ] power loss / kill / rename 途中中断のテストを追加する
- [ ] benchmark を追加する
- [ ] iOS / Android の保護クラス検証を追加する
- [ ] 禁止 PRAGMA とログ露出の検証を追加する

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
