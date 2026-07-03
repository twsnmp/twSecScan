package webscanner_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"twSecScan/modules/webscanner"
)

func TestAssetAuditor_Start(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret"))
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	auditor := webscanner.NewAssetAuditor()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pathsToCheck := []string{".env", "admin", "notfound"}
	resultsChan, err := auditor.Start(ctx, ts.URL, pathsToCheck, webscanner.AuditOptions{
		Concurrency: 2,
		Timeout:     1 * time.Second,
		Delay:       10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to start asset auditor: %v", err)
	}

	results := make(map[string]webscanner.AuditResult)
	for res := range resultsChan {
		results[res.Path] = res
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	// Verify .env
	resEnv, ok := results[".env"]
	if !ok || !resEnv.Exposed || resEnv.StatusCode != 200 || resEnv.Severity != "critical" {
		t.Errorf("Expected .env to be exposed as critical with status 200, got: %+v", resEnv)
	}

	// Verify admin
	resAdmin, ok := results["admin"]
	if !ok || !resAdmin.Exposed || resAdmin.StatusCode != 403 || resAdmin.Severity != "medium" {
		t.Errorf("Expected admin to be exposed as medium with status 403, got: %+v", resAdmin)
	}

	// Verify notfound
	resNF, ok := results["notfound"]
	if !ok || resNF.Exposed || resNF.StatusCode != 404 {
		t.Errorf("Expected notfound to be not exposed with status 404, got: %+v", resNF)
	}
}
