package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"twSecScan/core/models"
)

func TestNewClientFactory(t *testing.T) {
	// Test Ollama creation
	cfgOllama := &models.Config{
		ActiveProvider: "ollama",
		OllamaURL:      "http://localhost:11434",
		OllamaModel:    "llama3",
	}
	client, err := NewClient(cfgOllama)
	if err != nil {
		t.Fatalf("failed to create ollama client: %v", err)
	}
	if _, ok := client.(*OllamaClient); !ok {
		t.Errorf("expected *OllamaClient, got %T", client)
	}

	// Test OpenAI error without API key
	cfgOpenAIEmpty := &models.Config{
		ActiveProvider: "openai",
	}
	_, err = NewClient(cfgOpenAIEmpty)
	if err == nil {
		t.Error("expected error for OpenAI client without API key, got nil")
	}

	// Test OpenAI creation with API key
	cfgOpenAI := &models.Config{
		ActiveProvider: "openai",
		APIKeyOpenAI:   "sk-test",
	}
	client, err = NewClient(cfgOpenAI)
	if err != nil {
		t.Fatalf("failed to create openai client: %v", err)
	}
	if _, ok := client.(*OpenAIClient); !ok {
		t.Errorf("expected *OpenAIClient, got %T", client)
	}

	// Test Anthropic creation with API key
	cfgAnthropic := &models.Config{
		ActiveProvider:  "anthropic",
		APIKeyAnthropic: "secret-test",
	}
	client, err = NewClient(cfgAnthropic)
	if err != nil {
		t.Fatalf("failed to create anthropic client: %v", err)
	}
	if _, ok := client.(*AnthropicClient); !ok {
		t.Errorf("expected *AnthropicClient, got %T", client)
	}
}

func TestOllamaClient_AnalyzeFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("expected path /api/generate, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := ollamaGenerateResponse{Response: "test advice from ollama"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "llama3")
	advice, err := client.AnalyzeFinding(context.Background(), "test-target", "vulnerability", "desc", "proof")
	if err != nil {
		t.Fatalf("AnalyzeFinding failed: %v", err)
	}
	if advice != "test advice from ollama" {
		t.Errorf("expected 'test advice from ollama', got %s", advice)
	}
}

func TestOpenAIClient_AnalyzeFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected auth header Bearer test-key, got %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		var resp openaiChatResponse
		resp.Choices = append(resp.Choices, struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}{})
		resp.Choices[0].Message.Content = "test advice from openai"
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOpenAIClient("test-key")
	client.baseURL = server.URL // Override for test
	advice, err := client.AnalyzeFinding(context.Background(), "test-target", "vulnerability", "desc", "proof")
	if err != nil {
		t.Fatalf("AnalyzeFinding failed: %v", err)
	}
	if advice != "test advice from openai" {
		t.Errorf("expected 'test advice from openai', got %s", advice)
	}
}

func TestAnthropicClient_AnalyzeFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-anthropic-key" {
			t.Errorf("expected x-api-key header test-anthropic-key, got %s", r.Header.Get("x-api-key"))
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("expected anthropic-version header 2023-06-01, got %s", r.Header.Get("anthropic-version"))
		}
		w.Header().Set("Content-Type", "application/json")
		var resp anthropicResponse
		resp.Content = append(resp.Content, struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{Type: "text", Text: "test advice from anthropic"})
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewAnthropicClient("test-anthropic-key")
	client.baseURL = server.URL // Override for test
	advice, err := client.AnalyzeFinding(context.Background(), "test-target", "vulnerability", "desc", "proof")
	if err != nil {
		t.Fatalf("AnalyzeFinding failed: %v", err)
	}
	if advice != "test advice from anthropic" {
		t.Errorf("expected 'test advice from anthropic', got %s", advice)
	}
}
