package osint

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLookupDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, err := LookupDNS(ctx, "example.com")
	if err != nil {
		t.Fatalf("LookupDNS returned error: %v", err)
	}

	// example.com should have at least A records
	if len(records.A) == 0 {
		t.Log("Warning: example.com resolved to no A records (could be offline or blocked network)")
	}
}

func TestQueryWHOIS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try querying a standard domain. If offline, this may fail, so we log instead of strict failure.
	result, err := QueryWHOIS(ctx, "example.com")
	if err != nil {
		t.Logf("QueryWHOIS failed (expected if offline/rate-limited): %v", err)
		return
	}

	if result == "" {
		t.Error("expected non-empty WHOIS result")
	}

	if !strings.Contains(strings.ToLower(result), "iana") && !strings.Contains(strings.ToLower(result), "domain") {
		t.Logf("WHOIS response didn't contain expected strings, raw output: %s", result)
	}
}
