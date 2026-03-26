# Operations

`encryp-base` の導入・運用時に確認する方針をまとめた手引きです。

## Logging Policy

- 鍵、パスフレーズ、派生秘密、復号前データはログに出さない
- SQL の bind 値や生のファイルパスは、原則として出さない
- ログには操作名、phase、SQLite の result code、再試行可否だけを残す
- デバッグ用途でも、production 相当のビルドでは verbose trace を無効にする
- クラッシュレポートや解析基盤では、秘密情報を必ずマスクする

## Backup And Restore

- 既定のバックアップ経路は copy-swap ベースにする
- 暗号 DB の export / migrate / rekey は `encsqlite_checkpoint()` を前処理に含める
- 途中失敗に備えて、`source` / `dest.tmp` / `bak` / `phase` を記録する marker を使う
- アクティブ DB の単純なファイルコピーを正規バックアップ手順にしない
- 復元手順は、元の DB を壊さずに戻せることを前提にする

## Device Transfer

- device-bound mode は別端末への移行を前提にしない
- 端末移行が必要な製品は、サーバ再同期、passphrase mode、または別の escrow 設計を選ぶ
- 再インストール時の挙動は、OS の鍵保護とアプリ保存領域の扱いを踏まえて事前検証する
- バックアップ除外や復元制御が必要なら、製品要件として先に決める

## Unsupported Features

- `PRAGMA key` と SQL 文字列での鍵指定
- `ATTACH` / `DETACH` の一般利用
- `VACUUM` の直接実行
- `load_extension()`
- アプリ側での `journal_mode` 変更
- アプリ側での `mmap_size` 変更
- external storage への DB 配置
- shared container や複数プロセス前提の共有利用

## Release Checklist

- [ ] README と設計書のリンクが正しい
- [ ] `ROADMAP.md` と `TASKS.md` の内容が最新
- [ ] 対象 OS の鍵保護ポリシーが確定している
- [ ] 禁止 API と禁止 PRAGMA が実装方針に反映されている
- [ ] ログに秘密情報が出ないことを確認した
- [ ] バックアップ / 復元 / 移行の導線を確認した

## Reference

- [README](README.md)
- [ROADMAP](ROADMAP.md)
- [TASKS](TASKS.md)
- [SQLite 暗号化パッケージ設計書](doc/sqlite_encryption_package_design.md)
