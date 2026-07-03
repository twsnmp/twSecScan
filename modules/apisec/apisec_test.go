package apisec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoadOpenAPISpecAndFuzz(t *testing.T) {
	// 1. Setup a Mock Local Server serving OpenAPI specification and mock endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
  "openapi": "3.0.0",
  "info": {
    "title": "Test API Spec",
    "version": "1.0.0"
  },
  "paths": {
    "/users": {
      "get": {
        "parameters": [
          {
            "name": "id",
            "in": "query",
            "required": true,
            "schema": {
              "type": "integer"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "success"
          }
        }
      }
    }
  }
}`))
	})

	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		idStr := r.URL.Query().Get("id")
		if strings.Contains(idStr, "UNION") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Database error: syntax error near " + idStr))
			return
		}
		if strings.Contains(idStr, "<script>") {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("ID: " + idStr))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 2. Test Parser
	doc, err := LoadOpenAPISpec(ctx, ts.URL+"/openapi.json")
	if err != nil {
		t.Fatalf("Failed to load OpenAPI spec: %v", err)
	}

	endpoints := ExtractEndpoints(doc)
	if len(endpoints) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(endpoints))
	}

	endpoint := endpoints[0]
	if endpoint.Path != "/users" || endpoint.Method != "GET" {
		t.Errorf("Unexpected endpoint properties: %+v", endpoint)
	}

	// 3. Test Fuzzer
	fuzzer := NewAPIFuzzer()
	resultsChan, err := fuzzer.Start(ctx, endpoints, APIFuzzOptions{
		Concurrency: 2,
		Timeout:     1 * time.Second,
		BaseURL:     ts.URL,
	})
	if err != nil {
		t.Fatalf("Failed to start fuzzer: %v", err)
	}

	var findings []APIFuzzResult
	for res := range resultsChan {
		findings = append(findings, res)
	}

	// Validate fuzzer findings (expecting SQLi and XSS vulnerabilities to be flagged)
	foundSQLi := false
	foundXSS := false

	for _, finding := range findings {
		if finding.VulnerabilityType == "SQLi" {
			foundSQLi = true
		}
		if finding.VulnerabilityType == "XSS" {
			foundXSS = true
		}
	}

	if !foundSQLi {
		t.Error("Expected SQLi vulnerability to be detected")
	}
	if !foundXSS {
		t.Error("Expected XSS vulnerability to be detected")
	}
}
