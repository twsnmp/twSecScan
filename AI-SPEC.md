# twSecScan 開発指示書 (AI Agent Prompt & Spec)

## 1. プロジェクト概要 (Project Overview)

外部ツール（nmap, nuclei等）に依存しない、単一の実行ファイル（シングルバイナリ）で動作するクロスプラットフォーム対応の **AI駆動型セキュリティスキャナー デスクトップアプリケーション**。

### コア技術スタック & 開発環境

| コンポーネント         | 採用技術                                                                 |
|----------------------|------------------------------------------------------------------------|
| ビルド環境管理         | `mise` (.mise.toml) — Go / Node.js / Wails CLI のバージョン一元管理        |
| バックエンド           | Go言語（ピュアGo実装、Goroutine Worker Pool による並行処理）                |
| フロントエンド         | Wails v2 + Svelte 5 (Runes) + Tailwind CSS                             |
| データ永続化           | `go.etcd.io/bbolt` (純Go製組み込みKVS、CGO不要)                          |
| AI連携               | Ollama（ローカル）/ OpenAI / Anthropic の抽象化インターフェース              |
| OpenAPI パース        | `github.com/getkin/kin-openapi`                                         |
| ワードリスト           | `go:embed` でバイナリ内部に完全内蔵 (directories.txt / subdomains.txt)    |

---

## 2. 開発環境・ビルド構成

### A. .mise.toml

```toml
[tools]
go    = "1.26.4"
node  = "20.x"
wails = "2.x"
```

### B. wails.json

```json
{
  "$schema": "https://wails.io/schemas/config.v2.json",
  "name": "twSecScan",
  "outputfilename": "twSecScan",
  "frontend:dir": "frontend",
  "frontend:cmd:install": "npm install",
  "frontend:cmd:build": "npm run build",
  "frontend:dev:watcher": "npm run dev",
  "frontend:dev:serverUrl": "http://localhost:34116",
  "devserver": "localhost:34117",
  "author": { "name": "twsnmp-style-developer" }
}
```

### C. フロントエンド構成

Svelte 5 の Runes 機能 (`$state`, `$derived`) と Tailwind CSS で構築。
状態管理・多言語対応(i18n)は Svelte 5 Runes を使ったインライン実装（`translations` オブジェクト）。
`marked` ライブラリを使用して AI アドバイスの Markdown をレンダリング。

---

## 3. ディレクトリ構造 (Project Structure)

```
twSecScan/
├── .mise.toml                    # mise 環境管理ファイル
├── wails.json                    # Wails 設定ファイル
├── main.go                       # Wails アプリのエントリポイント
├── app.go                        # Wails Binding 構造体（Frontend-Backend仲介）
├── core/
│   ├── db/                       # bbolt を使用した永続化
│   │   └── bbolt.go              # config / scans / findings バケット管理
│   └── models/                   # Go構造体定義
│       └── models.go             # Config, Scan, Finding
├── modules/                      # 各種セキュリティスキャンモジュール（ピュアGo）
│   ├── ai/                       # LLMクライアント抽象化
│   │   ├── client.go             # LLMClient インターフェース + ファクトリ
│   │   ├── ollama.go             # Ollama 実装
│   │   ├── openai.go             # OpenAI 実装
│   │   └── anthropic.go          # Anthropic 実装
│   ├── apisec/                   # API セキュリティスキャン
│   │   ├── openapi_parser.go     # OpenAPI 3.0 スペック パーサー (kin-openapi)
│   │   └── fuzzer.go             # API エンドポイント ファザー
│   ├── osint/                    # OSINT / ネットワーク情報収集
│   │   ├── port_scanner.go       # TCPポートスキャン (net.DialTimeout + Worker Pool)
│   │   ├── dns_whois.go          # DNS/WHOIS 情報取得
│   │   └── crypto_scanner.go     # SSL/TLS・SSH・メール暗号設定検証
│   ├── webscanner/               # Webセキュリティスキャン
│   │   ├── crawler.go            # リンク切れ・HTTPヘッダ・PII検出クローラー
│   │   ├── dir_checker.go        # ディレクトリ・アセット 露出チェッカー (Asset Auditor)
│   │   ├── validation_tester.go  # XSS / SQL Injection 入力値検証テスター
│   │   ├── tech_detector.go      # 技術スタック検出（Webフィンガープリント）
│   │   └── test_server.go        # ローカル脆弱性模擬サーバー（開発・テスト用）
│   └── localaudit/
│       └── auditor.go            # ローカルフォルダ CIS Controls 準拠監査
├── embed/
│   ├── embed.go                  # go:embed による埋め込み定義
│   └── wordlists/
│       ├── directories.txt       # ディレクトリ探索用ワードリスト
│       └── subdomains.txt        # サブドメイン探索用ワードリスト
└── frontend/
    ├── package.json              # Vite, Svelte 5, Tailwind の定義
    └── src/
        ├── App.svelte            # メインコンポーネント（単一ファイル構成）
        ├── app.css               # グローバルスタイル
        └── main.js               # エントリポイント
```

---

## 4. データモデル (core/models/models.go)

```go
// Config: システム設定・AI認証情報
type Config struct {
    APIKeyOpenAI    string `json:"api_key_openai"`
    APIKeyAnthropic string `json:"api_key_anthropic"`
    OllamaURL       string `json:"ollama_url"`
    OllamaModel     string `json:"ollama_model"`
    ActiveProvider  string `json:"active_provider"` // "ollama" | "openai" | "anthropic"
    ScanConcurrency int    `json:"scan_concurrency"`
    Language        string `json:"language"`        // "en" | "ja" | "" (auto)
}

// Scan: スキャンタスクの実行記録
type Scan struct {
    ID           string         `json:"id"`
    Target       string         `json:"target"`
    Status       string         `json:"status"` // "pending" | "running" | "completed" | "failed" | "cancelled"
    StartTime    time.Time      `json:"start_time"`
    EndTime      time.Time      `json:"end_time"`
    FindingCount map[string]int `json:"finding_count"` // {"critical":0, "high":1, "medium":2, "low":0, "info":5}
    ErrorMsg     string         `json:"error_msg,omitempty"`
}

// Finding: スキャンで検出された脆弱性・発見事項
type Finding struct {
    ID          string    `json:"id"`
    ScanID      string    `json:"scan_id"`
    Target      string    `json:"target"`
    Module      string    `json:"module"` // 下記スキャンモジュール識別子を参照
    Title       string    `json:"title"`
    Description string    `json:"description"`
    Severity    string    `json:"severity"` // "info" | "low" | "medium" | "high" | "critical"
    Proof       string    `json:"proof"`
    AIAdvice    string    `json:"ai_advice,omitempty"`
    Timestamp   time.Time `json:"timestamp"`
}
```

---

## 5. スキャンモジュール詳細仕様

### 5.1 スキャンタイプと起動フロー

`app.go` の `StartScan(target, scanType, extra string)` が scanType を受け取り、対応する goroutine を起動する。

| scanType            | 起動関数                   | Finding.Module       | 説明                                         |
|---------------------|--------------------------|----------------------|----------------------------------------------|
| `osint` (default)   | `runPortScan`             | `osint`, `dns_whois` | TCPポートスキャン + DNS/WHOIS                   |
| `webscanner`        | `runWebScan`              | `webscanner`         | リンク切れ・HTTPヘッダ・PII検出                  |
| `asset_auditor`     | `runAssetAuditScan`       | `asset_auditor`      | 設定ファイル・バックアップ露出チェック              |
| `validation_tester` | `runValidationTesterScan` | `validation_tester`  | クローラー + XSS/SQLi 入力値検証               |
| `tech_detector`     | `runTechDetectorScan`     | `tech_detector`      | Webフィンガープリント（CMS・サーバー等検出）        |
| `apisec`            | `runAPISecScan`           | `apisec`             | OpenAPI スペック解析 + APIファジング             |
| `dns_whois`         | `runDNSWhoisScan`         | `dns_whois`          | DNS/WHOIS スタンドアロン実行                    |
| `crypto_scanner`    | `runCryptoScan`           | `crypto_scanner`     | SSL/TLS・SSH・SMTP/IMAP/POP3 暗号設定検証     |
| `local_audit`       | `runLocalAuditScan`       | `local_audit`        | ローカルフォルダ CIS Controls 準拠監査           |

### 5.2 OSINTスキャン (modules/osint/)

**ポートスキャン (`port_scanner.go`)**
- `ScanPorts(ctx, target, ports, timeout, concurrency)` で TCP接続を試行
- デフォルト対象ポート: `21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443`
- 重要ポートに応じて severity を動的に付与（Telnet: `high`, SMB: `high`, DB群: `medium`）
- 完了後、`executeDNSWhois` で DNS・WHOIS もあわせて取得

**DNS/WHOIS (`dns_whois.go`)**
- `LookupDNS(ctx, host)` — A / AAAA / MX / TXT / NS / CNAME レコードを取得
- `QueryWHOIS(ctx, host)` — WHOIS ポート(43)への直接接続でレジストラ情報を取得

**暗号設定検証 (`crypto_scanner.go`)**
- 対象プロトコル: HTTPS(443), SSH(22), SMTP(25/465/587), IMAP(143/993), POP3(110/995)
- TLS証明書の有効期限・プロトコルバージョン・暗号スイートを検査
- SSH バナー取得によるバージョン・鍵交換アルゴリズムの検証
- STARTTLS コマンドシーケンスによるメール系サービスの TLS 対応チェック

### 5.3 Webスキャナー (modules/webscanner/)

**クローラー (`crawler.go`)**
- `NewCrawler().Start(ctx, target, Options{})` — チャネルベースの非同期クロール
- 同一ドメイン内部リンクを再帰的に巡回
- 各URLで HTTP ヘッダ検査 (`header_checker.go`) と PII 検出を実施
- リンク切れ（非200/404）を Finding として報告

**HTTPヘッダ検査 (`header_checker.go`)**
- `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy` などの欠落・設定ミスを検出

**アセット監査 (`dir_checker.go`)**
- `embed/wordlists/directories.txt` のワードリストを使用
- HTTP 200 (露出) / 403 (存在確認) を Exposed として報告

**入力値検証テスター (`validation_tester.go`)**
- クローラーで収集した URL のクエリパラメータに XSS・SQLi ペイロードを注入
- レスポンス内のペイロード反射・エラーキーワードを検出

**技術スタック検出 (`tech_detector.go`)**
- HTTPレスポンスヘッダ・HTMLソース・特定パスへのプローブから CMS / Webサーバー / フレームワーク を識別

**テストサーバー (`test_server.go`)**
- ローカル脆弱性模擬サーバーを port 8081-8089 で起動/停止
- 安全な環境でのスキャン動作確認用（開発・デモ用途）

### 5.4 APIセキュリティ (modules/apisec/)

- `openapi_parser.go`: `getkin/kin-openapi` を使って OpenAPI 3.0 スペック（URL またはローカルファイル）を解析し、エンドポイント一覧を抽出
- `fuzzer.go`: 抽出したエンドポイントに対して各種ペイロードでファジングを実施し、異常レスポンスを検出
- `StartScan` の `extra` パラメータで API ベース URL を上書き可能

### 5.5 ローカルフォルダ監査 (modules/localaudit/)

- `auditor.go`: ローカルフォルダを再帰的に走査し CIS Controls に基づく監査を実施
- 検出対象: シークレット/認証情報の露出、危険なファイルパーミッション、SSH/ネットワーク設定ミス、不要なバックアップファイル
- 最大1000ファイル・1MBまでを対象とし、`node_modules`, `.git`, `vendor` 等は除外

---

## 6. LLM 抽象化 (modules/ai/)

```
LLMClient interface {
    AnalyzeFinding(ctx, target, title, description, proof string) (string, error)
}
```

- `ai.NewClient(cfg *models.Config) (LLMClient, error)` — ファクトリ関数
  - `cfg.ActiveProvider == "ollama"` → `OllamaClient` (デフォルト `http://localhost:11434`)
  - `cfg.ActiveProvider == "openai"` → `OpenAIClient`
  - `cfg.ActiveProvider == "anthropic"` → `AnthropicClient`
- 全スキャン関数で Finding ごとに `AnalyzeFinding` を呼び出し、`Finding.AIAdvice` に格納

---

## 7. データ永続化 (core/db/bbolt.go)

bbolt の単一ファイル DB (`twSecScan.db`) を使用。

| バケット名  | キー          | 値                      |
|-----------|-------------|-------------------------|
| `config`  | `"config"`  | `models.Config` JSON    |
| `scans`   | `scan.ID`   | `models.Scan` JSON      |
| `findings`| `finding.ID`| `models.Finding` JSON   |

**主要メソッド:**
- `GetConfig() / SaveConfig(cfg)`
- `ListScans() / GetScan(id) / SaveScan(scan) / DeleteScan(id)`
- `SaveFinding(finding) / ListFindingsByScan(scanID)`

---

## 8. フロントエンド UI/UX (frontend/src/App.svelte)

- **単一 `.svelte` ファイル**構成
- **ナビゲーション**: Dashboard / Scan History / Settings の3ページ
- **多言語対応**: `translations` オブジェクト (en / ja) + OS言語自動検出
- **スキャンモジュール選択**: UI上でドロップダウンによりスキャンタイプを選択
- **ローカルフォルダ選択**: Wails `OpenDirectoryDialog` API を使用
- **OpenAPI ファイル選択**: Wails `OpenFileDialog` API を使用 (JSON/YAML/YML)
- **テストサーバー制御**: Dashboard内でローカルテストサーバーの起動/停止トグル
- **AI アドバイス表示**: `marked` ライブラリによる Markdown → HTML レンダリング
- **レポートエクスポート**: Wails `SaveFileDialog` で HTML / Markdown / JSON を選択して保存

---

## 9. レポートエクスポート (app.go)

`ExportScanReport(scanID string) (string, error)` — 以下の3形式に対応:

| 拡張子  | 内容                                                                 |
|--------|----------------------------------------------------------------------|
| `.html`| `generateHTMLReport` — Go テンプレートで生成するスタイル付きレポート (言語対応) |
| `.md`  | `generateMarkdownReport` — Markdown テキストレポート (言語対応)           |
| `.json`| `json.MarshalIndent` — `{scan, findings}` 構造体をそのまま出力            |
