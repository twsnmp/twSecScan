package webscanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidationTester_Vulnerabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		dbID := r.URL.Query().Get("id")

		if q != "" {
			// Vulnerable to XSS: reflects back raw HTML / scripts
			if strings.Contains(q, "<script>") || strings.Contains(q, "<img>") {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>Result: " + q + "</body></html>"))
				return
			}
		}

		if dbID != "" {
			// Vulnerable to SQLi: check SQLi payload and return simulated error
			if strings.Contains(dbID, "'") || strings.Contains(dbID, "UNION") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Fatal: SQL syntax error near FROM table"))
				return
			}
		}

		// Safe fallback
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	tester := NewValidationTester()
	ctx := context.Background()

	t.Run("Detect XSS vulnerability", func(t *testing.T) {
		targetURLs := []string{server.URL + "/?q=test"}
		resultsChan, err := tester.Start(ctx, targetURLs, ValidationOptions{Concurrency: 2})
		if err != nil {
			t.Fatalf("failed to start tester: %v", err)
		}

		var results []ValidationResult
		for res := range resultsChan {
			results = append(results, res)
		}

		foundXSS := false
		for _, r := range results {
			if r.VulnerabilityType == "XSS" && r.Vulnerable {
				foundXSS = true
				if r.Severity != "high" {
					t.Errorf("expected high severity for XSS, got %s", r.Severity)
				}
				if !strings.Contains(r.Proof, "XSS payload reflected") {
					t.Errorf("unexpected proof: %s", r.Proof)
				}
			}
		}

		if !foundXSS {
			t.Error("expected to find XSS vulnerability")
		}
	})

	t.Run("Detect SQLi vulnerability", func(t *testing.T) {
		targetURLs := []string{server.URL + "/?id=123"}
		resultsChan, err := tester.Start(ctx, targetURLs, ValidationOptions{Concurrency: 2})
		if err != nil {
			t.Fatalf("failed to start tester: %v", err)
		}

		var results []ValidationResult
		for res := range resultsChan {
			results = append(results, res)
		}

		foundSQLi := false
		for _, r := range results {
			if r.VulnerabilityType == "SQLi" && r.Vulnerable {
				foundSQLi = true
				if r.Severity != "critical" && r.Severity != "high" {
					t.Errorf("expected high or critical severity for SQLi, got %s", r.Severity)
				}
			}
		}

		if !foundSQLi {
			t.Error("expected to find SQLi vulnerability")
		}
	})
}

func TestValidationTester_Safe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Secure/sanitized page
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Safe content (no reflection, no SQL errors)"))
	}))
	defer server.Close()

	tester := NewValidationTester()
	ctx := context.Background()

	targetURLs := []string{server.URL + "/?q=safe&id=safe"}
	resultsChan, err := tester.Start(ctx, targetURLs, ValidationOptions{Concurrency: 2})
	if err != nil {
		t.Fatalf("failed to start tester: %v", err)
	}

	var results []ValidationResult
	for res := range resultsChan {
		results = append(results, res)
	}

	if len(results) > 0 {
		t.Errorf("expected 0 vulnerabilities detected for safe URL, got %d: %+v", len(results), results)
	}
}

func TestValidationTester_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewValidationTester()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	targetURLs := []string{server.URL + "/?q=test"}
	resultsChan, err := tester.Start(ctx, targetURLs, ValidationOptions{Concurrency: 2})
	if err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	// Should close immediately and return no/few results (or exit cleanly)
	select {
	case _, ok := <-resultsChan:
		if ok {
			// Could be finished if executed extremely fast, but context cancel is checked.
		}
	case <-time.After(1 * time.Second):
		t.Error("tester did not respond to context cancellation promptly")
	}
}
