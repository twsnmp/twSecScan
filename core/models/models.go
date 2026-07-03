package models

import "time"

// Config represents the system settings, database configurations, and LLM credentials.
type Config struct {
	APIKeyOpenAI     string `json:"api_key_openai"`
	APIKeyAnthropic  string `json:"api_key_anthropic"`
	OllamaURL        string `json:"ollama_url"`
	OllamaModel      string `json:"ollama_model"`
	ActiveProvider   string `json:"active_provider"` // "ollama", "openai", "anthropic"
	ScanConcurrency  int    `json:"scan_concurrency"`
}

// Scan represents a single scanning task execution and its status.
type Scan struct {
	ID           string            `json:"id"`
	Target       string            `json:"target"`
	Status       string            `json:"status"` // "pending", "running", "completed", "failed", "cancelled"
	StartTime    time.Time         `json:"start_time"`
	EndTime      time.Time         `json:"end_time"`
	FindingCount map[string]int    `json:"finding_count"` // e.g., {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 5}
	ErrorMsg     string            `json:"error_msg,omitempty"`
}

// Finding represents a security vulnerability or discovery found during a scan.
type Finding struct {
	ID          string    `json:"id"`
	ScanID      string    `json:"scan_id"`
	Target      string    `json:"target"`
	Module      string    `json:"module"` // e.g., "osint", "webscanner", "apisec"
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // "info", "low", "medium", "high", "critical"
	Proof       string    `json:"proof"`
	AIAdvice    string    `json:"ai_advice,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}
