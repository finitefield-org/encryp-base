# SQLite 暗号化パッケージ設計書

_iOS / Android アプリ内で利用する SQLite データベースの保存時暗号化_

詳細設計・実装指針・運用設計

| **対象範囲: モバイル端末に保存される SQLite 本体・WAL・rollback journal・statement journal の機密保護** |
|---------------------------------------------------------------------------------------------------------|

| **項目**   | **内容**                                                                                                       |
|------------|----------------------------------------------------------------------------------------------------------------|
| 文書種別   | 詳細設計書 / セキュリティ設計書                                                                                |
| 版数       | v1.0（ドラフト）                                                                                               |
| 作成日     | 2026-03-26                                                                                                     |
| 想定読者   | モバイル基盤チーム、セキュリティレビュー担当、SQLite 組み込み担当、QA                                          |
| 設計の要点 | Pager 境界でのページ暗号化、OS セキュアストレージによる鍵保護、copy-swap による移行 / rekey、TEMP のメモリ固定 |

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p><strong>採用決定（要約）</strong></p>
<blockquote>
<p>• SQLite の Pager / Codec 境界に最小パッチを入れ、永続化されるページ像を暗号化する。</p>
<p>• DB 本体と WAL / rollback journal / statement journal では、同一の canonical encrypted page image を再利用する。</p>
<p>• 鍵は 32-byte DEK を基本とし、iOS は Keychain、Android は Keystore で保護する。</p>
<p>• 公開 API では SQL の PRAGMA key を使わず、C API / Swift wrapper / JNI wrapper からのみ鍵を渡す。</p>
<p>• 平文移行と rekey は in-place ではなく、新規ファイル生成 → backup API → fsync → atomic rename の copy-swap 方式とする。</p>
</blockquote></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 文書構成

> 1\. 目的と適用範囲
>
> 2\. 要件整理
>
> 3\. 脅威モデルと非対象
>
> 4\. 全体アーキテクチャ
>
> 5\. 暗号方式とオンディスク形式
>
> 6\. 鍵管理と OS 統合
>
> 7\. SQLite 統合方針
>
> 8\. 公開 API 仕様
>
> 9\. データベースのライフサイクル
>
> 10\. 運用ポリシーと制約
>
> 11\. テスト / 検証計画
>
> 12\. 実装ロードマップ
>
> 付録 A. 採用しない案
>
> 付録 B. 標準設定ベースライン
>
> 付録 C. 参考資料

# 1. 目的と適用範囲

本設計の目的は、iOS と Android のアプリケーション内部に保存される SQLite データベースを、アプリ開発者が通常の SQLite API に近い使い勝手を維持したまま保存時暗号化できるようにすることである。対象は main database file に加え、WAL、rollback journal、statement journal まで含む。SQLite の pager / journaling の前提と整合する設計にすることで、単純なファイルラッパでは取りこぼしやすい永続化経路を減らす。\[R1\]\[R3\]\[R4\]\[R7\]\[R8\]

本書は v1 の詳細設計であり、暗号アルゴリズム、ページ形式、キー階層、OS ごとの鍵保護、SQLite への差し込み位置、API、移行手順、運用制約、テスト観点までを定義する。実装時の裁量を減らすため、推奨値だけでなく、禁止事項と先送り事項も明示する。

守る対象は、端末上に保存された SQLite コンテンツの機密性と改ざん検知である。実行中プロセスの完全な乗っ取り、root / jailbreak 後のメモリダンプ、アプリに埋め込まれた共通鍵の抽出、端末外部からの古い DB スナップショットへのロールバックは、本設計だけでは完全には防げない。SEE もページ内容はメモリ上では平文になると説明しており、この点は SQLite 暗号化一般の前提である。\[R7\]

### 1.1 スコープ

| **区分**         | **含める**                                                      | **含めない / v1 非対象**                                       |
|------------------|-----------------------------------------------------------------|----------------------------------------------------------------|
| データ保護       | main DB、WAL、rollback journal、statement journal、削除痕の低減 | 実行中メモリ、root / jailbreak、端末外への完全な anti-rollback |
| プラットフォーム | iOS / Android のアプリ private storage                          | 外部共有ストレージ、他 OS 向けビルド                           |
| API              | C API、Swift wrapper、JNI / Room wrapper                        | SQL 文字列での鍵指定、任意 SQL 拡張ロード                      |
| 移行             | 平文→暗号化、rekey、export                                      | in-place rekey、任意 ATTACH 運用                               |

# 2. 要件整理

要件は、機能要件、セキュリティ要件、運用要件、保守要件に分けて扱う。v1 は “少ない例外で確実に守る” を優先し、柔軟性より一貫性を取る。

### 2.1 要件一覧

| **ID** | **要件**                                         | **設計反映**                                                           |
|--------|--------------------------------------------------|------------------------------------------------------------------------|
| F-01   | 既存 SQLite API に近い開発体験を維持する         | 暗号化は pager 境界で透過実施。公開 API は sqlite3\* を返す。          |
| F-02   | iOS / Android の双方で同一 DB フォーマットを扱う | AES-256-GCM + 共通 page layout + 共通 key hierarchy を採用。           |
| F-03   | 平文 DB から移行できる                           | backup API を使った copy-swap migratePlaintext() を提供。              |
| S-01   | ページ単位の改ざんを検知する                     | AEAD tag で各ページを検証。ページ番号を AAD に束縛。                   |
| S-02   | 鍵を SQL やログに露出しない                      | PRAGMA key 不採用。SQL trace と debug log では鍵関連文字列を禁止。     |
| S-03   | OS の secure storage を活用する                  | iOS Keychain / Android Keystore を鍵保護層として使用。                 |
| O-01   | SQLite アップストリームへの追従を可能にする      | パッチ面積を pager / wal / open 初期化周辺に限定。                     |
| O-02   | TEMP 系での平文 spill を極小化する               | SQLITE_TEMP_STORE=3、temp_store=MEMORY、stmt journal spill=-1。        |
| M-01   | ファイル破損と誤鍵を識別しやすくする             | page 1 検証失敗を専用エラーに正規化し、後続ページ失敗は CORRUPT 扱い。 |

# 3. 脅威モデルと非対象

本設計は “端末上に置かれたファイルの保護” を主目的にし、攻撃者の能力を段階的に定義する。特に、SQLite は DB 本体以外にも複数の補助ファイルを扱うため、どこまで暗号化対象にするかを脅威モデルと一体で定義する。\[R4\]

### 3.1 攻撃者モデル

| **攻撃者** | **想定能力**                                            | **防御可否 / 備考**                                                       |
|------------|---------------------------------------------------------|---------------------------------------------------------------------------|
| A1         | 端末を紛失し、オフラインでアプリ private storage を取得 | 防御対象。DB / WAL / journal のページ内容を読めない。                     |
| A2         | 同一端末上の別アプリだが root 権限なし                  | 防御対象。private storage と secure storage の隔離に依存。                |
| A3         | クラウド / ローカルバックアップ経由でファイル一式を取得 | 防御対象。ただし device-bound key は新端末で復元不能となる。              |
| A4         | root / jailbreak、Frida、ptrace、メモリダンプ           | 原則非対象。実行中の平文ページや鍵派生後の秘密が露出し得る。              |
| A5         | 古い DB スナップショットを差し戻すロールバック攻撃      | 完全防御はしない。必要ならサーバ同期や monotonic counter を別設計で追加。 |

### 3.2 残るメタデータ漏えい

| **項目**                   | **v1 の扱い**                                                                                                      |
|----------------------------|--------------------------------------------------------------------------------------------------------------------|
| ファイルの存在・サイズ     | 隠さない。DB の存在、概算サイズ、更新頻度の推測は可能。                                                            |
| WAL / journal の存在       | 隠さない。ファイル名とサイズから transaction activity は推測され得る。                                             |
| WAL / journal の構造ヘッダ | SQLite 互換を優先し、構造ヘッダは平文のままにする。ページ image 自体は canonical encrypted page image を格納する。 |
| ページ再生攻撃             | 同一 DB 内の古い整合スナップショット差し戻しは別機構が必要。v1 では anti-rollback を持たない。                     |

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p><strong>設計上の重要な前提</strong></p>
<blockquote>
<p>• 改ざん検知は “そのページが壊れた / 入れ替えられた” ことを検出するが、“より古い正当な DB 全体” への巻き戻しは防がない。</p>
<p>• メモリ上では SQLite が平文ページを扱うため、保存時暗号化は live compromise の万能対策ではない。</p>
<p>• 共有ストレージやアプリ埋め込み共通鍵での配布は、本設計の保護境界の外側にある。</p>
</blockquote></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 4. 全体アーキテクチャ

暗号化は SQLite の VFS 全置換ではなく、Pager 境界に codec を差し込む方式を基本とする。SQLite の内部アーキテクチャでは pager がページキャッシュ、WAL / rollback、耐障害性、OS I/O を仲介しており、ページが永続化される境界として最も自然である。\[R1\]\[R2\]\[R3\]

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>App / ORM<br />
</strong>Room / GRDB / 既存 DAO</th>
<th><strong>EncSQLite API<br />
</strong>open / rekey / migrate</th>
<th><strong>SQLite Core + Codec<br />
</strong>pager / wal / open 初期化</th>
<th><strong>Crypto Core<br />
</strong>AES-GCM / HKDF / Argon2</th>
<th><strong>OS Key Store + FS<br />
</strong>Keychain / Keystore / private storage</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

アプリ層からは通常の SQLite に近い API を見せつつ、保存境界でのみ暗号化 / 復号を行う。

### 4.1 コンポーネント責務

| **コンポーネント**         | **責務**                                                | **備考**                                  |
|----------------------------|---------------------------------------------------------|-------------------------------------------|
| encsqlite_core             | 公開 API、設定、エラー正規化、authorizer / PRAGMA 固定  | C ABI を提供し、各言語 wrapper から利用。 |
| encsqlite_codec            | ページ暗号化 / 復号、page 1 特例、reserved bytes の管理 | SQLite パッチの中心。                     |
| encsqlite_crypto           | AEAD、HKDF、Argon2、RNG、zeroize                        | プロバイダ抽象化を持つ。                  |
| encsqlite_keystore_ios     | Keychain item 管理、file protection 設定                | ThisDeviceOnly を既定にする。             |
| encsqlite_keystore_android | Keystore 鍵生成、DEK wrap / unwrap                      | StrongBox 利用可なら優先。                |
| encsqlite_migrator         | 平文移行、rekey、export、checkpoint / fsync / rename    | copy-swap のみを実装。                    |

# 5. 暗号方式とオンディスク形式

v1 のフォーマットは 4 KiB fixed page size を前提とし、各ページの末尾 reserved bytes に AEAD メタデータを格納する。SQLite は reserved bytes を持てるため、ページの usable size を減らすことで per-page metadata を配置できる。\[R2\]\[R7\]\[R8\]

### 5.1 採用アルゴリズム

| **要素**          | **採用値**      | **理由**                                                                               |
|-------------------|-----------------|----------------------------------------------------------------------------------------|
| 対称暗号          | AES-256-GCM     | 機密性と改ざん検知を 1 パスで提供。モバイル CPU の AES 支援を利用しやすい。\[R16\]     |
| KDF（passphrase） | Argon2id        | memory-hard でオフライン総当たり耐性が高い。\[R14\]                                    |
| 鍵派生            | HKDF-SHA-256    | 単一 root secret から役割ごとの subkey を簡潔に分離できる。\[R15\]                     |
| 乱数              | OS CSPRNG       | iOS / Android のシステム RNG を使用。                                                  |
| ページサイズ      | 4096 bytes 固定 | SQLite の既定・モバイルの I/O 特性・reserved bytes 36 とのバランスがよい。\[R2\]\[R3\] |
| reserved bytes    | 36 bytes        | nonce 16 + tag 16 + key_epoch 4 を収める。                                             |

## 5.2 canonical encrypted page image

DB 本体、WAL、rollback journal、statement journal では、同一の canonical encrypted page image を使用する。つまり、暗号化済みページ表現はファイル種別ごとに再暗号化しない。SQLite の WAL checkpoint や rollback はページ image をコピーする動作であり、同一表現に統一すると checkpoint / rollback での再暗号化が不要になる。v1 では file-kind を AAD に含めない。

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Page &gt; 1 (4096 bytes physical)</p>
<p>+------------------------------------ 4060 bytes -----------------------------------+------16------+------16------+----4----+</p>
<p>| AES-256-GCM ciphertext of logical page bytes 0..4059 | nonce[16] | tag[16] | epoch |</p>
<p>+------------------------------------------------------------------------------------+--------------+--------------+---------+</p>
<p>Page 1 (4096 bytes physical)</p>
<p>+------16------+------------------------------- 4044 bytes ---------------------------+------16------+------16------+----4----+</p>
<p>| db_salt[16] | AES-256-GCM ciphertext of logical page-1 bytes 16..4059 | nonce[16] | tag[16] | epoch |</p>
<p>+--------------+---------------------------------------------------------------------+--------------+--------------+---------+</p>
<p>In-memory logical page 1:</p>
<p>bytes 0..15 = "SQLite format 3\0" をライブラリが合成</p>
<p>bytes 16..4059 = 復号結果</p>
<p>bytes 4060..4095 = SQLite から見せない / 0 埋め</p></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

page 1 の先頭 16 byte は固定文字列であり、保存時に機密性のある内容ではないため、v1 ではそれをディスクに保存せず、代わりに DB ごとの salt を配置する。復号時は page 1 の AEAD 検証に成功した後、メモリ上で “SQLite format 3\0” を補う。これは SQLCipher 系の実装が page 1 先頭に salt を置く方針と整合する。\[R8\]

### 5.3 ページメタデータ

| **フィールド** | **長さ** | **内容**                                                                                                          |
|----------------|----------|-------------------------------------------------------------------------------------------------------------------|
| db_salt        | 16 bytes | page 1 先頭に置く DB 固有 salt。device-bound / passphrase のどちらでも HKDF / KDF の salt として使う。            |
| nonce          | 16 bytes | 各ページ書き込みごとに新規生成するランダム IV。96-bit ではなく 128-bit とし、長期運用での衝突余地をさらに下げる。 |
| tag            | 16 bytes | AES-GCM 認証タグ。                                                                                                |
| key_epoch      | 4 bytes  | キー世代番号。v1 は 1 固定を基本とするが、将来の background rekey / rolling migration のために予約する。          |

## 5.4 AAD と改ざん検知

AES-GCM の AAD は以下で固定する。AAD にページ番号と page size を含めることで、ページ入れ替えや異なる DB からの移植を検出しやすくする。DB 全体の fresheness（古いスナップショットへの巻き戻し防止）は別問題であり、AAD だけでは解けない。

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p>AAD_v1 = ASCII("encsqlite-page-v1")</p>
<p>|| db_salt[16]</p>
<p>|| be32(page_no)</p>
<p>|| be32(page_size)</p>
<p>|| be32(key_epoch)</p>
<p>Plaintext_v1(page&gt;1) = logical_page[0 .. 4059]</p>
<p>Plaintext_v1(page1) = logical_page[16 .. 4059]</p></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

公開エラーは以下に正規化する。page 1 検証が通らない場合は “鍵が誤っている / 想定外フォーマット” を返し、page 1 は通るが後続ページで tag 不一致が起きた場合は “破損 / 改ざん” とみなす。内部的には SQLite の NOTADB / CORRUPT / IOERR を使い分ける。

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p><strong>v1 で明示的に扱わないもの</strong></p>
<blockquote>
<p>• ファイル全体の anti-rollback。攻撃者が古い DB 一式を差し戻した場合、それが整合していれば AEAD は成立し得る。</p>
<p>• WAL / journal の構造ヘッダ機密化。ページ image の秘匿を優先し、SQLite 互換を崩さない。</p>
<p>• page size の可変化。v1 は 4096 固定にして open / migrate / test を簡単にする。</p>
</blockquote></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 6. 鍵管理と OS 統合

鍵管理は “DB をどう暗号化するか” と “その鍵を OS 上でどう保護するか” を分離して設計する。DB 自体は 32-byte root secret を前提に共通フォーマットで暗号化し、その root secret の入手方法だけを device-bound mode と passphrase mode で切り替える。

### 6.1 キー階層

| **層**      | **内容**                                                | **保存場所 / 備考**                                        |
|-------------|---------------------------------------------------------|------------------------------------------------------------|
| Root secret | 32-byte DEK もしくは Argon2id(passphrase, db_salt) 出力 | device-bound では OS secure storage、passphrase では非保存 |
| K_master    | HKDF-Extract(db_salt, root secret)                      | open 時にメモリ上で派生                                    |
| K_page      | HKDF-Expand(K_master, 'encsqlite/page/v1', 32)          | ページ暗号化専用                                           |
| K_aux       | HKDF-Expand(K_master, 'encsqlite/aux/v1', 32)           | 将来の export manifest / side metadata 予約                |

## 6.2 device-bound mode（既定）

既定モードでは、DB 作成時に 256-bit ランダム DEK を生成し、それを OS の secure storage に結び付けて保持する。DB ファイルには鍵を置かない。復号に必要な db_salt は DB page 1 に格納されるが、salt 自体は秘密ではない。

このモードの特徴は、ユーザーにパスフレーズ入力を求めず、open が速いことである。一方で、バックアップから別デバイスへ復元した場合、ThisDeviceOnly Keychain や Android Keystore の non-exportable key は移送されないため、DB ファイルだけ復元されても開けない。設計上これは正しい挙動であり、recoverable backup が必要なプロダクトは別の key escrow / export 機構を追加する。\[R9\]\[R11\]\[R22\]

## 6.3 passphrase mode（オプション）

passphrase mode では、ユーザー入力の passphrase を Argon2id に通し、32-byte root secret を得る。v1 では cleartext metadata を持たないため、KDF パラメータは “format profile” に束縛し、open 時に候補プロファイルを順に試す方式とする。新規作成では P1 を使い、将来互換のため旧プロファイル P0 を import 時のみ受け付ける。\[R14\]

### 6.4 Passphrase profile

| **Profile** | **Argon2id パラメータ**                            | **用途**               |
|-------------|----------------------------------------------------|------------------------|
| P1          | memory=64 MiB, iterations=3, parallelism=1, out=32 | v1 新規作成の既定      |
| P0          | memory=32 MiB, iterations=3, parallelism=1, out=32 | 旧端末互換 / import 用 |

## 6.5 iOS 実装方針

iOS では Keychain を主たる secure storage とし、DEK を generic password item として保存する。既定の accessibility class は kSecAttrAccessibleWhenUnlockedThisDeviceOnly とし、端末が unlock 状態のときだけ取得でき、かつ別端末に移行されない性質を利用する。アプリが background fetch 等でロック後も DB を開く必要がある場合に限り、ポリシーを明示して AfterFirstUnlock 系に下げる。\[R9\]\[R20\]

DB ファイル自体には NSFileProtectionComplete を既定とし、バックグラウンドで再オープンする要件がある場合のみ completeUntilFirstUserAuthentication に変更可能とする。Keychain と File Protection は役割が異なるため、両方を組み合わせて使う。\[R10\]\[R13\]

### 6.6 iOS 鍵保護ポリシー

| **項目**        | **既定**                              | **例外**                                                                      |
|-----------------|---------------------------------------|-------------------------------------------------------------------------------|
| DEK 保存        | Keychain / WhenUnlockedThisDeviceOnly | 明示要件がある場合のみ AfterFirstUnlockThisDeviceOnly                         |
| DB ファイル保護 | NSFileProtectionComplete              | background reopen が必要な場合のみ weaker class に変更                        |
| 共有コンテナ    | 非推奨                                | どうしても必要なら plaintext-header compatibility mode を別プロファイルで設計 |

## 6.7 Android 実装方針

Android では Android Keystore で non-exportable な wrapping key を生成し、ランダム DEK を AES-GCM で wrap した blob を app-specific internal storage に置く。DB 本体も internal storage に置き、external storage には保存しない。StrongBox が使える端末では wrapping key を StrongBox 優先で生成する。\[R11\]\[R12\]\[R13\]

Direct Boot 対応が本当に必要な最小データだけを別 DB に分離し、main DB は credential encrypted storage 前提とする。device-bound mode の DB は Auto Backup / device transfer で別端末に移ると unwrap できないため、プロダクト側で backup exclusion か再同期戦略を決める。\[R22\]

### 6.8 Android 鍵保護ポリシー

| **項目**     | **既定**                             | **例外 / 注意**                                         |
|--------------|--------------------------------------|---------------------------------------------------------|
| DEK 保護     | Keystore wrapping key + wrapped blob | 高感度用途では user-auth-bound key を選択可             |
| DB 保存先    | internal storage                     | external storage には置かない                           |
| Direct Boot  | 非対応                               | 別 DB に切り出す場合のみ専用設計                        |
| バックアップ | device-bound では移送不可が既定      | recoverable backup が必要なら別設計で key escrow を追加 |

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p><strong>実装上の注意</strong></p>
<blockquote>
<p>• Passphrase は Java / Kotlin String や Swift String に長く保持しない。mutable byte buffer で受け取り、派生後に zeroize する。</p>
<p>• DEK、K_master、K_page は secure allocator 上に置き、close / error path の全分岐で消去する。</p>
<p>• 鍵や passphrase そのものはログ、クラッシュレポート、トレースに出さない。</p>
</blockquote></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 7. SQLite 統合方針

SQLite への差し込みは、完全な独自ストレージエンジン化ではなく “最小パッチの pager codec” を基本とする。VFS だけで全てを覆う案は temp file や partial write まで含めた取り扱いが複雑になりやすく、初版では pager 境界に集中した方が実装とレビューの両方で有利である。\[R1\]\[R3\]\[R18\]

### 7.1 主要パッチポイント

| **箇所**             | **役割**              | **実施内容**                                                       |
|----------------------|-----------------------|--------------------------------------------------------------------|
| DB open 初期化       | codec context 作成    | page_size=4096、reserve=36、db_salt 読み込み、policy PRAGMA 固定。 |
| pager read path      | ディスク→メモリ復号   | page 1 は salt + ciphertext を処理し、SQLite ヘッダを合成する。    |
| pager write path     | メモリ→ディスク暗号化 | dirty page から canonical encrypted page image を生成する。        |
| wal / journal 経路   | 補助ファイル対応      | ページ image を canonical 形式のまま格納 / 再利用する。            |
| backup / migrate API | 安全な移行            | checkpoint / fsync / rename を含む copy-swap を共通化する。        |

## 7.2 TEMP と spill の扱い

SQLite は rollback journals、WAL、statement journals、TEMP databases、materialization、transient index、VACUUM 用一時 DB など、複数種の一時ファイルを使う。\[R4\] v1 では、暗号化の中心は main DB 系に置きつつ、平文 spill を減らすため以下を固定する。

### 7.3 SQLite ベースライン設定

| **設定**                                     | **値** | **意図**                                                          |
|----------------------------------------------|--------|-------------------------------------------------------------------|
| SQLITE_TEMP_STORE                            | 3      | TEMP database / sorter / materialization を既定でメモリに寄せる。 |
| sqlite3_config(SQLITE_CONFIG_STMTJRNL_SPILL) | -1     | statement journal を常にメモリ保持する。\[R23\]                   |
| PRAGMA temp_store                            | MEMORY | temp b-tree のディスク spill を避ける。                           |
| PRAGMA mmap_size                             | 0      | memory-mapped I/O を無効化する。\[R17\]                           |
| PRAGMA trusted_schema                        | OFF    | 危険な schema 駆動機能の有効化を避ける。\[R5\]                    |
| SQLITE_DBCONFIG_DEFENSIVE                    | 1      | 危険な操作を制限する。\[R5\]                                      |
| PRAGMA cell_size_check                       | ON     | 破損 DB 検出を強める。                                            |
| PRAGMA foreign_keys                          | ON     | 通常の整合性設定。                                                |
| PRAGMA secure_delete                         | FAST   | 削除痕を減らしつつ I/O 増を抑える。\[R19\]                        |

raw VACUUM は v1 では許可しない。VACUUM は一時 DB を使い、ファイルサイズや削除痕対策の意味では有用だが、暗号化設計としては copy-swap の migrate / rekey / compact API で代替する方が制御しやすい。\[R4\]\[R6\]

## 7.4 許可しない / wrapper 経由に限定する操作

| **操作**                | **扱い**         | **理由**                                                         |
|-------------------------|------------------|------------------------------------------------------------------|
| PRAGMA key / cipher\_\* | 非対応           | 鍵を SQL 文字列に乗せないため。                                  |
| ATTACH / DETACH         | v1 では原則禁止  | 複数 key context と temp / journal policy の複雑化を避けるため。 |
| VACUUM                  | 直接実行禁止     | 一時 DB 経由の平文 spill と挙動差を避けるため。                  |
| PRAGMA journal_mode     | アプリ側変更禁止 | 暗号化経路と durability policy を固定するため。                  |
| PRAGMA mmap_size        | アプリ側変更禁止 | 暗号化境界の外で OS に map させないため。                        |
| load_extension()        | 無効化           | 攻撃面を減らすため。                                             |

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p><strong>FTS に関する注意</strong></p>
<blockquote>
<p>• SQLite は secure_delete を有効にしても FTS3 / FTS5 の shadow table に forensic trace が残り得ると案内している。[R19]</p>
<p>• 全文検索を使う場合は、delete policy、rebuild 手順、compact/export 手順を別途運用に含める。</p>
<p>• v1 では “FTS を使っても暗号 DB の外に平文が出ない” ことと “削除痕が完全に消える” ことを混同しない。</p>
</blockquote></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 8. 公開 API 仕様

公開 API は “通常の sqlite3\* を返す open 系 API” を中心にし、暗号化固有の処理だけを別関数に切り出す。方針は、アプリケーションコードに鍵文字列を SQL として流させないこと、そして migrate / rekey のような危険操作を独自 API に閉じ込めることである。

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p>typedef enum {</p>
<p>ENCSQLITE_KEY_DEVICE_BOUND = 1,</p>
<p>ENCSQLITE_KEY_PASSPHRASE = 2,</p>
<p>ENCSQLITE_KEY_RAW_32 = 3 // test / migration only</p>
<p>} encsqlite_key_type;</p>
<p>typedef struct {</p>
<p>encsqlite_key_type type;</p>
<p>const void *data;</p>
<p>size_t data_len;</p>
<p>} encsqlite_key_material;</p>
<p>typedef struct {</p>
<p>int create_if_missing;</p>
<p>int read_only;</p>
<p>int expect_application_id;</p>
<p>uint32_t application_id;</p>
<p>int journal_mode_wal;</p>
<p>} encsqlite_open_options;</p></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

### 8.1 主要 API

| **API**                       | **役割**                          | **備考**                                    |
|-------------------------------|-----------------------------------|---------------------------------------------|
| encsqlite_open_v2()           | 暗号 DB を開く / 必要なら新規作成 | 成功時に sqlite3\* を返す。                 |
| encsqlite_migrate_plaintext() | 平文 DB を暗号 DB に移行          | checkpoint、backup API、rename を内部実行。 |
| encsqlite_rekey_copy_swap()   | 新しい鍵で DB を再生成            | in-place rekey はしない。                   |
| encsqlite_export()            | 別パスに暗号 DB を出力            | compact モードを将来拡張可能。              |
| encsqlite_checkpoint()        | 明示 checkpoint / truncate        | 移行やバックアップの前処理。                |
| encsqlite_close_secure()      | close + secure cleanup            | secret zeroize と policy cleanup を行う。   |

## 8.2 言語別 wrapper

| **プラットフォーム** | **ラッパ**                            | **方針**                                                          |
|----------------------|---------------------------------------|-------------------------------------------------------------------|
| iOS                  | Swift wrapper                         | FMDB / GRDB から使いやすい open 関数と policy struct を提供する。 |
| Android              | JNI + SupportSQLiteOpenHelper.Factory | Room で差し替え可能にする。                                       |
| 共有                 | C API                                 | テスト・ベンチマーク・CLI でも同じ API を使う。                   |

## 8.3 エラー正規化

| **公開エラー**               | **内部原因の例**                          | **扱い**                                        |
|------------------------------|-------------------------------------------|-------------------------------------------------|
| ENCSQLITE_BAD_KEY_OR_FORMAT  | page 1 tag 失敗、salt 不正、想定外 header | 再試行可。パスフレーズ再入力や key ref 見直し。 |
| ENCSQLITE_CORRUPT            | page 1 は成功したが後続ページで tag 失敗  | DB 破損として扱う。recover/export を試みる。    |
| ENCSQLITE_IO                 | fsync / rename / xWrite 失敗              | 一時障害またはストレージ枯渇。                  |
| ENCSQLITE_POLICY_VIOLATION   | 禁止 PRAGMA、禁止 SQL、unsupported ATTACH | アプリ側バグとして扱う。                        |
| ENCSQLITE_UNSUPPORTED_FORMAT | page size 不一致、将来フォーマット        | 明示 upgrade が必要。                           |

デバッグログには SQLite の result code、I/O エラー、migration ステップ番号だけを出し、path / key / SQL bind value を出さない。Android では log disclosure が一般的な問題になるため、production build では verbose trace を無効にする。\[R24\]

# 9. データベースのライフサイクル

作成、open、migrate、rekey、recover の各ライフサイクルは、暗号フォーマットだけでなくクラッシュ安全性まで含めて定義する。特に rekey を in-place で行わないことが、実装・テスト・復旧の簡素化に効く。

## 9.1 新規作成

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p>1) app generates or obtains root secret</p>
<p>2) generate db_salt[16]</p>
<p>3) create empty DB in rollback-journal mode</p>
<p>4) set page_size=4096, reserve=36, application_id, user_version</p>
<p>5) attach codec context and create schema</p>
<p>6) switch to WAL if policy says WAL</p>
<p>7) fsync DB, fsync directory</p>
<p>8) store / finalize OS key reference</p></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## 9.2 既存暗号 DB を開く

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p>1) read first 16 bytes</p>
<p>2) if header starts with 'SQLite format 3\0':</p>
<p>-&gt; plaintext DB (caller may reject or invoke migrate)</p>
<p>3) obtain root secret from device store or passphrase</p>
<p>4) derive K_master / K_page</p>
<p>5) verify page 1 tag and synthesize logical SQLite header</p>
<p>6) validate page_size=4096, reserve=36, application_id</p>
<p>7) install authorizer / fixed PRAGMAs / defensive settings</p>
<p>8) return sqlite3*</p></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## 9.3 平文→暗号化 migrate

migratePlaintext() は copy-swap 専用とする。source DB が WAL なら先に checkpoint(TRUNCATE) をかけ、source を読み取り専用で開き、dest 側に新規暗号 DB を作る。SQLite backup API でコピーし、dest に対して quick_check を実行し、fsync 後に atomic rename で入れ替える。\[R6\]\[R3\]

| **ステップ** | **処理**                               | **クラッシュ時の扱い**            |
|--------------|----------------------------------------|-----------------------------------|
| 1            | source を checkpoint / readonly open   | source は不変のまま残る           |
| 2            | dest.tmp を新規暗号 DB として作成      | 失敗時は tmp を削除               |
| 3            | backup API で全ページコピー            | source 不変。再試行可能           |
| 4            | dest quick_check / application_id 検証 | 失敗時は dest を破棄              |
| 5            | fsync(dest), fsync(parent dir)         | rename 直前までは source が正本   |
| 6            | rename(source→bak, dest→source)        | 中断時は recovery marker から回復 |
| 7            | bak を安全削除 or 次回起動で回収       | rename 完了後のみ旧 DB を廃棄     |

## 9.4 rekey

rekey は migrate と同じ copy-swap を使い、source が暗号 DB である点だけが異なる。source を既存キーで開き、dest.tmp を新キーで作り、backup API でコピーする。これにより “途中で一部ページだけ新鍵になった DB” を作らない。

## 9.5 compact / export

削除痕の更なる除去やファイル縮小が必要なケースでは export() を使う。通常 export は backup API ベースとし、CPU / I/O を抑える。より小さいファイルと forensic trace 削減を優先するモードが必要なら、将来 compact export を VACUUM INTO 互換の専用経路として実装する。\[R6\]\[R19\]

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p><strong>Recovery marker</strong></p>
<blockquote>
<p>• migrate / rekey / export の途中では、親ディレクトリに小さな marker ファイルを置き、source, dest.tmp, bak, phase を記録する。</p>
<p>• 次回起動時に marker が残っていれば、rename の完了可否を検査してロールフォワード / ロールバックを決定する。</p>
<p>• marker には鍵そのものを入れず、path hash と state のみを記録する。</p>
</blockquote></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 10. 運用ポリシーと制約

暗号化パッケージは “何でもできる SQLite” ではなく、守るために使い方を少し制限する SQLite として運用する。プロダクトチームはこの制約を理解した上で採用する必要がある。

### 10.1 既定運用

| **項目**           | **既定値**                   | **備考**                                                                    |
|--------------------|------------------------------|-----------------------------------------------------------------------------|
| journal_mode       | WAL                          | 読み性能と通常運用の安定性を優先。page_size 変更は WAL 前に固定する。\[R3\] |
| synchronous        | NORMAL                       | モバイルのレイテンシとバッテリーの妥協点。高信頼用途では FULL を選択可。    |
| wal_autocheckpoint | 1000 pages                   | 既定値を踏襲。ワークロードにより調整。                                      |
| connection policy  | 長寿命 connection を再利用   | open/close の繰り返しを避ける。passphrase mode では特に重要。\[R8\]         |
| exclusive locking  | 単一プロセス前提の製品のみ可 | shared-memory file を減らしたい場合のオプション。\[R4\]                     |

shared container、複数プロセス同時アクセス、Widget / extension からの共有利用は v1 の既定スコープ外とする。必要であれば iOS の plaintext-header compatibility mode を含む別プロファイルで再設計する。

## 10.2 ログ・監視

監視指標としては open 成功率、page 1 認証失敗件数、後続ページ認証失敗件数、migrate / rekey 成功率、checkpoint 所要時間、I/O エラー件数を持つ。ログには key ref の内部 ID と phase を残してもよいが、鍵や passphrase 自体は出さない。DB の絶対パスも可能な限り hash 化する。

## 10.3 バックアップ / 端末移行

device-bound mode を既定とする限り、暗号 DB は “同一端末でのみ開ける” のが基本挙動である。したがって、端末移行やアプリ再インストール後の復元が必要な製品では、(a) DB をサーバ再同期可能にする、(b) export 用 recovery key を別管理する、(c) passphrase mode を採用する、のいずれかを明示的に選ぶ必要がある。

# 11. テスト / 検証計画

テストは “SQLite の意味論が壊れていないこと” と “暗号境界が壊れていないこと” の二軸で行う。後者は tag failure、page swap、power loss、partial write、rename 途中中断などを重視する。

### 11.1 テストマトリクス

| **分類**             | **観点**                              | **具体例**                                                   |
|----------------------|---------------------------------------|--------------------------------------------------------------|
| 単体                 | 暗号 primitives                       | AES-GCM / HKDF / Argon2 の known-answer test、zeroize path。 |
| 単体                 | page codec                            | page\>1 / page1 special case、nonce/tag 配置、AAD 一致。     |
| 結合                 | SQLite 通常機能                       | create / insert / update / delete / txn / WAL checkpoint。   |
| 結合                 | 移行                                  | plain→enc、enc→rekey、途中失敗からの recovery marker 回復。  |
| 耐障害               | power loss / kill                     | journal 作成中、rename 直前、rename 後 bak 削除前。          |
| 改ざん               | bit flip / page swap / stale aux file | 1 bit 反転、別 page すり替え、古い WAL を差し戻し。          |
| 性能                 | mobile benchmark                      | open p50/p95、txn throughput、large scan overhead。          |
| 互換                 | SQLite アップストリーム追従           | 新しい SQLite amalgamation への再ベースライン。              |
| プラットフォーム     | OS 保護クラス                         | iOS lock/unlock、Android reboot 後 unlock 前後。             |
| セキュリティレビュー | コード / 設定                         | 禁止 PRAGMA、load_extension 無効、ログ露出なし。             |

CI では、平文 SQLite と暗号版 SQLite の SQL 結果が一致することを differential test で確認する。加えて、同一 workload で DB 本体・WAL・journal のいずれにも平文シグネチャが残らないことをバイト列スキャンで確認する。

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p><strong>必須の破壊テスト</strong></p>
<blockquote>
<p>• page 1 tag を壊して open が BAD_KEY_OR_FORMAT になること。</p>
<p>• page 1 は通るが page N tag を壊して CORRUPT になること。</p>
<p>• page 5 を page 6 に丸ごと置換して tag failure になること。</p>
<p>• 旧 WAL を差し戻したとき、少なくとも SQLite の整合性チェックと運用上の anti-rollback 前提が文書通りであること。</p>
</blockquote></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 12. 実装ロードマップ

| **段階** | **内容**                          | **完了条件**                                                          |
|----------|-----------------------------------|-----------------------------------------------------------------------|
| Phase 0  | フォーマット PoC                  | page1 / page\>1 の encrypt/decrypt、open/create が通る。              |
| Phase 1  | Pager 統合                        | WAL / rollback / statement journal を含む基本トランザクションが安定。 |
| Phase 2  | iOS / Android keystore 実装       | device-bound mode の end-to-end open/create/migrate が通る。          |
| Phase 3  | migrate / rekey / recovery marker | クラッシュ挿入テストと rename recovery が安定。                       |
| Phase 4  | wrapper / ORM 統合                | Swift wrapper、Room factory、サンプルアプリが完成。                   |
| Phase 5  | セキュリティレビューと負荷試験    | 設計レビュー完了、テスト matrix 通過、運用文書作成。                  |

アップストリーム追従のため、SQLite amalgamation への差分は 1 つの patch set とし、Pager / WAL / open 初期化 / public API 以外へ拡散させない。新しい SQLite リリースが出るたびに differential test と fault injection test を再実行する。

# 付録 A. 採用しない案

| **案**                                   | **採用しない理由**                                                                                  |
|------------------------------------------|-----------------------------------------------------------------------------------------------------|
| VFS 全置換での暗号化                     | temp file、partial write、page 1 特例、WAL 互換まで含めて複雑化しやすく、初版のレビュー負荷が高い。 |
| CBC + HMAC（SQLCipher 旧来型に近い構成） | 2 パスになりやすく、AEAD 1 本化の方が設計が単純。                                                   |
| in-place rekey                           | 途中失敗時に混在状態が生まれ、回復とテストが難しい。                                                |
| アプリ埋め込み共通鍵で seed DB を配布    | 解析者に対する実効性が弱く、端末ごとの秘密にならない。                                              |
| 可変 page size の広範サポート            | format / test matrix が膨れ、v1 の品質確保を難しくする。                                            |

# 付録 B. 標準設定ベースライン

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p>Creation-time defaults</p>
<p>page_size = 4096</p>
<p>reserve_size = 36</p>
<p>journal_mode = WAL</p>
<p>synchronous = NORMAL</p>
<p>temp_store = MEMORY</p>
<p>mmap_size = 0</p>
<p>secure_delete = FAST</p>
<p>trusted_schema = OFF</p>
<p>foreign_keys = ON</p>
<p>cell_size_check = ON</p>
<p>stmtjrnl_spill = -1</p>
<p>application_id = product-specific constant</p>
<p>Forbidden in production</p>
<p>PRAGMA key / raw SQL keying</p>
<p>ATTACH / DETACH (unless future explicit API exists)</p>
<p>VACUUM (use compact/export API instead)</p>
<p>load_extension()</p>
<p>app-controlled mmap_size / journal_mode changes</p></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 付録 C. 参考資料

本文の設計判断は主に以下の公開資料を参照している。リンクは文書名に埋め込んでいる。

**\[R1\]** [<u>Architecture of SQLite</u>](https://sqlite.org/arch.html)

**\[R2\]** [<u>Database File Format</u>](https://sqlite.org/fileformat.html)

**\[R3\]** [<u>Write-Ahead Logging</u>](https://sqlite.org/wal.html)

**\[R4\]** [<u>Temporary Files Used By SQLite</u>](https://sqlite.org/tempfiles.html)

**\[R5\]** [<u>Defense Against The Dark Arts</u>](https://sqlite.org/security.html)

**\[R6\]** [<u>C/C++ Interface For SQLite Version 3</u>](https://sqlite.org/capi3ref.html)

**\[R7\]** [<u>SQLite Encryption Extension: Documentation</u>](https://www.sqlite.org/see/doc/trunk/www/readme.wiki)

**\[R8\]** [<u>SQLCipher Design - Security Approach and Features</u>](https://www.zetetic.net/sqlcipher/design/)

**\[R9\]** [<u>Apple: kSecAttrAccessibleWhenUnlockedThisDeviceOnly</u>](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly)

**\[R10\]** [<u>Apple: NSFileProtectionComplete</u>](https://developer.apple.com/documentation/Foundation/FileProtectionType/complete?language=objc)

**\[R11\]** [<u>Android Keystore system</u>](https://developer.android.com/privacy-and-security/keystore)

**\[R12\]** [<u>Android data and file storage overview</u>](https://developer.android.com/training/data-storage)

**\[R13\]** [<u>Android: Sensitive Data Stored in External Storage</u>](https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage)

**\[R14\]** [<u>RFC 9106 - Argon2 Memory-Hard Function for Password Hashing</u>](https://datatracker.ietf.org/doc/rfc9106/)

**\[R15\]** [<u>RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</u>](https://datatracker.ietf.org/doc/html/rfc5869)

**\[R16\]** [<u>NIST SP 800-38D - Galois/Counter Mode (GCM) and GMAC</u>](https://csrc.nist.gov/pubs/sp/800/38/d/final)

**\[R17\]** [<u>Memory-Mapped I/O</u>](https://www.sqlite.org/mmap.html)

**\[R18\]** [<u>SQLite VFS</u>](https://www.sqlite.org/vfs.html)

**\[R19\]** [<u>PRAGMA secure_delete / FTS5 secure-delete notes</u>](https://sqlite.org/pragma.html)

**\[R20\]** [<u>Apple: Item attribute keys and values</u>](https://developer.apple.com/documentation/security/item-attribute-keys-and-values)

**\[R22\]** [<u>Android: Security recommendations for backups</u>](https://developer.android.com/privacy-and-security/risks/backup-best-practices)

**\[R23\]** [<u>SQLITE_CONFIG_STMTJRNL_SPILL</u>](https://sqlite.org/c3ref/c_config_covering_index_scan.html)

**\[R24\]** [<u>Android: Log Info Disclosure</u>](https://developer.android.com/privacy-and-security/risks/log-info-disclosure)

注: R21 は本文では未使用。番号を固定したまま残すと混乱するため欠番としている。