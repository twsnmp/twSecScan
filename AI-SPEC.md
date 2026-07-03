twSecScan 開発指示書 (AI Agent Prompt & Spec)

1. プロジェクト概要 (Project Overview)
Python製のセキュリティツール「Security Suite」のロジックをベースに、外部ツール（nmap, nuclei等）に依存しない、単一の実行ファイル（シングルバイナリ）で動作するクロスプラットフォーム対応のAI駆動型デスクトップアプリケーション 「twSecScan」 を開発する。
コア技術スタック & 開発環境
• ビルドツール（環境管理）: mise を利用して Go, Node.js, Wails CLI のバージョンを一元管理する。
• バックエンド: Go言語 (ピュアGo実装、並行処理・Worker Poolによる最適化)
• フロントエンド: Wails v2 + Svelte 5 + Tailwind CSS + Shadcn-Svelte (Melt UI)
• データ永続化: go.etcd.io/bbolt (純Go製組み込みKVS、外部DB・CGO不要)
• AI連携: ローカルの Ollama API（デフォルト）および OpenAI/Anthropic の抽象化インターフェース。
• ワードリスト: 実用的な探索辞書を go:embed でバイナリ内部に完全内蔵。

2. 開発環境・ビルド構成 (参考: twsnmp/twgps)

A. .mise.toml （または mise.toml）
プロジェクトのルートに配置し、ツールチェーンを固定する。
[tools]
go = "1.22.0"
node = "20.0.0"
wails = "2.9.1"

B. wails.json
出力バイナリ名、フロントエンドのビルドコマンド等を定義する。
{
"$schema": "https://wails.io/schemas/config.v2.json",
"name": "twSecScan",
"outputfilename": "twSecScan",
"frontend:dir": "frontend",
"frontend:cmd:install": "npm install",
"frontend:cmd:build": "npm run build",
"frontend:dev:watcher": "npm run dev",
"frontend:dev:serverUrl": "http://localhost:34115",
"author": { "name": "twsnmp-style-developer" }
}

C. フロントエンド構成 (frontend/package.json)
Svelte 5 の Runes 機能（$state, $derived）を前提とし、Vite + Tailwind CSS で構築する。状態管理や多言語対応（i18n）は、Svelte 5 のルーンを利用した軽量なオブジェクトでピュアに実装する。

3. ディレクトリ構造 (Project Structure)
twSecScan/
├── .mise.toml             # mise 環境管理ファイル
├── wails.json             # Wails 設定ファイル
├── main.go                # Wails アプリのエントリポイント
├── app.go                 # Wails Binding 構造体（Frontend-Backend仲介）
├── core/
│   ├── db/                # bbolt を使用した永続化 (config, scans, findingsバケット)
│   ├── config/            # 設定管理
│   ├── exporters/         # HTML/JSON/Markdown レポート出力
│   └── models/            # Scan, Finding, Config などのGo構造体定義
├── modules/               # 各種セキュリティスキャンモジュール（ピュアGo）
│   ├── ai/                # LLMクライアント（Ollama, OpenAI, Anthropic）
│   ├── apisec/            # OpenAPI 3.0パーサー、APIファザー
│   ├── osint/             # ポートスキャン(net.Dial)、DNS列挙、WHOIS
│   └── webscanner/        # クローラー、XSS/SQLi簡易チェッカー
├── embed/                 # バイナリ内蔵リソース
│   ├── wordlists/         # ディレクトリ・サブドメイン探索用ワードリスト（テキスト）
│   └── embed.go           # go:embed による埋め込み定義
└── frontend/              # Svelte 5 フロントエンド UI
├── package.json       # Vite, Svelte 5, Tailwind の定義
└── src/
├── App.svelte     # メインコンポーネント
└── lib/           # Wails Binding 呼び出し・UIコンポーネント層

4. 各モジュールの詳細仕様
- bboltによる永続化 (core/db/bbolt.go) • 起動時に twSecScan.db を自動生成（またはオープン）。 • config バケットにLLM設定、scans に履歴、findings に脆弱性情報をJSONシリアライズして保存。
- ピュアGoスキャナー (modules/osint/, modules/webscanner/) • 外部の nmap 等は呼び出さず、net.DialTimeout を使用。Goroutine の同時実行数を制御する Worker Pool を実装し、インメモリで高速にポートスキャンやディレクトリ探索を行う。 • すべてのスキャンタスクは context.Context を受け取り、UI側からのキャンセルやタイムアウトに安全に対応する。
- LLM抽象化 (modules/ai/) • LLMClient インターフェースを定義。ローカルの Ollama（http://localhost:11434）をデフォルトとし、設定で OpenAI / Anthropic に切り替えられるファクトリパターンを実装。
- 初心者向けUI/UX (Svelte 5) • 「ターゲットURL/IPを入力してスキャンボタンを押すだけ」の1クリック設計。 • スキャン進行状況をプログレスバーやステータスステップで視覚的に表現する。

