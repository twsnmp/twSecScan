package ai

import (
	"context"
	"fmt"

	"twSecScan/core/models"
)

// LLMClient represents the interface to interact with an AI model provider.
type LLMClient interface {
	AnalyzeFinding(ctx context.Context, target, title, description, proof string) (string, error)
}

// NewClient creates an LLMClient based on the active provider in Config.
func NewClient(cfg *models.Config) (LLMClient, error) {
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
		return NewOllamaClient(url, model), nil
	case "openai":
		if cfg.APIKeyOpenAI == "" {
			return nil, fmt.Errorf("OpenAI API key is required but not provided")
		}
		return NewOpenAIClient(cfg.APIKeyOpenAI), nil
	case "anthropic":
		if cfg.APIKeyAnthropic == "" {
			return nil, fmt.Errorf("Anthropic API key is required but not provided")
		}
		return NewAnthropicClient(cfg.APIKeyAnthropic), nil
	default:
		return nil, fmt.Errorf("unknown LLM active provider: %s", cfg.ActiveProvider)
	}
}

// buildSystemPrompt returns a common system prompt used for finding analysis.
func buildSystemPrompt() string {
	return "You are a professional security consultant. Analyze the provided security finding and give clear, concise remediation advice."
}

// buildUserPrompt formats the finding details into a prompt.
func buildUserPrompt(target, title, description, proof string) string {
	return fmt.Sprintf("Target: %s\nFinding Title: %s\nDescription: %s\nProof/Detail: %s\n\nProvide actionable remediation steps.",
		target, title, description, proof)
}
