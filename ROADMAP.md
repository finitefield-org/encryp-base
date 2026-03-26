# Roadmap

`encryp-base` の実装フェーズを、上流追従と検証を見据えて並べたロードマップです。

## フェーズ一覧

| Phase | 目的 | 主な成果物 | 完了条件 |
|---|---|---|---|
| Phase 0 | 基盤整備 | リポジトリ構成、CI、SQLite 取り込み方針、開発規約 | 実装前提の作業環境が揃う |
| Phase 1 | フォーマット PoC | page 1 / page > 1 の暗号化形式、AAD、reserved bytes 定義 | encrypt / decrypt の往復が通る |
| Phase 2 | Pager 統合 | pager codec、WAL / journal 経路、エラー正規化 | 基本トランザクションが安定する |
| Phase 3 | 鍵管理統合 | iOS Keychain、Android Keystore、device-bound / passphrase mode | open / create / migrate が通る |
| Phase 4 | 移行と復旧 | copy-swap migrate、rekey、recovery marker | クラッシュ挿入後も復旧できる |
| Phase 5 | API / wrapper 統合 | C API、Swift wrapper、JNI / Room wrapper | アプリから安全に利用できる |
| Phase 6 | 検証とリリース準備 | security review、fault injection、benchmark、運用文書 | 設計レビューとテスト matrix を通過する |

## 実行順の考え方

- 先にページ形式と暗号境界を固定する
- 次に SQLite の pager / WAL / journal へ統合する
- 鍵保護は iOS / Android で並行して進める
- migrate / rekey / recovery は copy-swap を前提に最後に固める
- wrapper と運用文書は基盤が安定してからまとめる

## 参照

- [README](README.md)
- [SQLite 暗号化パッケージ設計書](doc/sqlite_encryption_package_design.md)
