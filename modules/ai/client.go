package ai

import (
	"context"
	"fmt"
	"os"
	"strings"

	"twSecScan/core/models"
)

// LLMClient represents the interface to interact with an AI model provider.
type LLMClient interface {
	AnalyzeFinding(ctx context.Context, target, title, description, proof string) (string, error)
}

// DetectLanguage returns the language to use ("en" or "ja") based on the config.
func DetectLanguage(lang string) string {
	if lang == "auto" || lang == "" {
		for _, env := range []string{"LANG", "LC_ALL", "LC_MESSAGES"} {
			val := os.Getenv(env)
			if val != "" {
				if strings.HasPrefix(strings.ToLower(val), "ja") {
					return "ja"
				}
				break
			}
		}
		return "en"
	}
	return lang
}

// NewClient creates an LLMClient based on the active provider in Config.
func NewClient(cfg *models.Config) (LLMClient, error) {
	lang := DetectLanguage(cfg.Language)
	switch cfg.ActiveProvider {
	case "ollama":
		url := cfg.OllamaURL
		if url == "" {
			url = "http://localhost:11434"
		}
		model := cfg.OllamaModel
		if model == "" {
			model = "llama3"
		}
		return NewOllamaClient(url, model, lang), nil
	case "openai":
		if cfg.APIKeyOpenAI == "" {
			return nil, fmt.Errorf("OpenAI API key is required but not provided")
		}
		return NewOpenAIClient(cfg.APIKeyOpenAI, lang), nil
	case "anthropic":
		if cfg.APIKeyAnthropic == "" {
			return nil, fmt.Errorf("Anthropic API key is required but not provided")
		}
		return NewAnthropicClient(cfg.APIKeyAnthropic, lang), nil
	default:
		return nil, fmt.Errorf("unknown LLM active provider: %s", cfg.ActiveProvider)
	}
}

// buildSystemPrompt returns a common system prompt used for finding analysis.
func buildSystemPrompt(lang string) string {
	if lang == "ja" {
		return "あなたはプロのセキュリティコンサルタントです。提供されたセキュリティ検出事項を分析し、明確で簡潔な対策アドバイスを日本語で提供してください。"
	}
	return "You are a professional security consultant. Analyze the provided security finding and give clear, concise remediation advice in English."
}

// buildUserPrompt formats the finding details into a prompt.
func buildUserPrompt(target, title, description, proof, lang string) string {
	if lang == "ja" {
		return fmt.Sprintf("対象: %s\n検出事項のタイトル: %s\n説明: %s\n証拠/詳細: %s\n\n実用的な対策手順を日本語で提供してください。回答はマークダウン形式で出力してください。",
			target, title, description, proof)
	}
	return fmt.Sprintf("Target: %s\nFinding Title: %s\nDescription: %s\nProof/Detail: %s\n\nProvide actionable remediation steps in English. Output your response in Markdown format.",
		target, title, description, proof)
}
