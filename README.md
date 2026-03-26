# encryp-base

`encryp-base` は、iOS / Android アプリ内で利用する SQLite データベースを保存時暗号化するための設計リポジトリです。

現時点では実装本体は初期段階で、`doc/sqlite_encryption_package_design.md` にまとめた詳細設計書と、SQLite のビルド基盤を中心に管理しています。

## 目的

- main DB に加えて WAL / rollback journal / statement journal まで含めて保護する
- SQLite の pager / codec 境界で暗号化し、通常の SQLite API に近い利用感を維持する
- iOS では Keychain、Android では Keystore を使って鍵を保護する
- 平文 DB からの移行や rekey を copy-swap 方式で安全に行う

## 設計の要点

| 項目 | 内容 |
|---|---|
| 暗号方式 | AES-256-GCM |
| KDF | Argon2id |
| 鍵派生 | HKDF-SHA-256 |
| ページサイズ | 4096 bytes 固定 |
| reserved bytes | 36 bytes |
| 鍵保護 | iOS Keychain / Android Keystore |
| 移行方式 | backup API + fsync + atomic rename による copy-swap |

## スコープ

### 含めるもの

- main DB
- WAL
- rollback journal
- statement journal
- iOS / Android の private storage
- C API / Swift wrapper / JNI wrapper

### 含めないもの

- root / jailbreak / メモリダンプ対策
- ファイル一式に対する完全な anti-rollback
- external storage
- SQL 文字列での鍵指定
- in-place rekey
- `ATTACH` / `DETACH` の一般利用
- `VACUUM`
- `load_extension()`

## 提供予定 API

| API | 役割 |
|---|---|
| `encsqlite_open_v2()` | 暗号 DB を開く / 必要なら新規作成する |
| `encsqlite_migrate_plaintext()` | 平文 DB を暗号 DB に移行する |
| `encsqlite_rekey_copy_swap()` | 新しい鍵で DB を再生成する |
| `encsqlite_export()` | 別パスへ暗号 DB を出力する |
| `encsqlite_checkpoint()` | 明示 checkpoint / truncate を行う |
| `encsqlite_close_secure()` | close と secret zeroize をまとめて行う |

## SQLite への統合方針

- SQLite そのものを別ストレージエンジン化せず、pager 境界に codec を差し込む
- DB 本体と補助ファイルには同じ canonical encrypted page image を使う
- TEMP 系の平文 spill を減らすため、`SQLITE_TEMP_STORE=3` や `temp_store=MEMORY` を前提にする
- 以下はアプリ側から変更させない
  - `PRAGMA key`
  - `PRAGMA journal_mode`
  - `PRAGMA mmap_size`
  - `load_extension()`

## 既定の運用ポリシー

| 項目 | 既定値 |
|---|---|
| `journal_mode` | `WAL` |
| `synchronous` | `NORMAL` |
| `wal_autocheckpoint` | `1000 pages` |
| `temp_store` | `MEMORY` |
| `mmap_size` | `0` |
| `trusted_schema` | `OFF` |
| `SQLITE_DBCONFIG_DEFENSIVE` | `1` |
| `cell_size_check` | `ON` |
| `foreign_keys` | `ON` |
| `secure_delete` | `FAST` |

## ライフサイクル

1. 新規作成
2. 既存暗号 DB を open
3. 平文 DB を migrate
4. rekey を copy-swap で実行
5. export / compact
6. recovery marker で中断復旧

## テスト観点

- AES-GCM / HKDF / Argon2 の単体検証
- page 1 と page 2 以降の暗号化 / 復号検証
- 通常の SQLite 動作確認
- 破損ページ、page swap、古い WAL の差し戻し
- power loss や rename 途中中断を含む耐障害試験
- iOS / Android の鍵保護クラス確認
- 禁止 PRAGMA やログ露出の確認

## 開発計画

- ロードマップ: [ROADMAP.md](ROADMAP.md)
- タスク一覧: [TASKS.md](TASKS.md)
- 運用手引き: [OPERATIONS.md](OPERATIONS.md)

## Repository Layout

- `include/encsqlite/`: public headers
- `src/`: core library sources
- `tests/`: smoke tests
- `third_party/sqlite/3510300/`: pinned SQLite amalgamation 3.51.3
- `wrappers/ios/`: Swift wrapper placeholder
- `wrappers/android/`: JNI / Room wrapper placeholder
- `scripts/`: maintenance helpers
- `.github/workflows/`: CI

## Build

Prerequisites:

- CMake 3.22 or newer
- A C11-capable compiler such as `clang` or `gcc`

1. `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release`
2. `cmake --build build --parallel`
3. `ctest --test-dir build --output-on-failure`

## SQLite Baseline

- Version: `3.51.3`
- Import method: vendored amalgamation from `sqlite-amalgamation-3510300.zip`
- Refresh helper: `scripts/fetch_sqlite.sh`

## 参考

- [SQLite 暗号化パッケージ設計書](doc/sqlite_encryption_package_design.md)
