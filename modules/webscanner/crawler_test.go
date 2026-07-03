package webscanner_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"twSecScan/modules/webscanner"
)

func TestCrawler_Start(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string]int)

	// Set up local test server to simulate a website with links
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()

		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			// Return HTML containing:
			// 1. A valid internal link: /about
			// 2. A broken internal link: /broken
			// 3. An external link (will simulate external host manually in resolved URL if we could, or just point to a distinct path or simulated external URL)
			// For testing external url resolved handling, we'll return a link to a different domain.
			// 4. Various PII elements
			fmt.Fprint(w, `
				<html>
				<body>
					<a href="/about">About Us</a>
					<a href="/broken">Broken Link</a>
					<a href="https://example.com/external">External Link</a>
					<p>Contact: test-user@example.com or 03-1234-5678.</p>
					<p>Zip: 100-0001</p>
					<p>CC: 4111-1111-1111-1111</p>
				</body>
				</html>
			`)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			// /about links to a nested /about/team link
			fmt.Fprint(w, `
				<html>
				<body>
					<a href="/about/team">Our Team</a>
				</body>
				</html>
			`)
		case "/about/team":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body>Team Page</body></html>")
		case "/broken":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	crawler := webscanner.NewCrawler()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resultsChan, err := crawler.Start(ctx, ts.URL, webscanner.Options{
		Concurrency: 2,
		Timeout:     1 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to start crawler: %v", err)
	}

	results := make(map[string]webscanner.LinkResult)
	for res := range resultsChan {
		results[res.URL] = res
	}

	// Verify the checked pages
	expectedURLs := []string{
		ts.URL,
		ts.URL + "/about",
		ts.URL + "/about/team",
		ts.URL + "/broken",
		"https://example.com/external",
	}

	for _, u := range expectedURLs {
		res, exists := results[u]
		if !exists {
			t.Errorf("Expected URL %s was not checked", u)
			continue
		}

		switch u {
		case ts.URL:
			if res.Broken {
				t.Errorf("Base URL should not be broken")
			}
			if res.StatusCode != 200 {
				t.Errorf("Base URL expected status 200, got %d", res.StatusCode)
			}
			
			// Verify PII detection
			expectedPII := map[string]string{
				"Email":      "test-user@example.com",
				"Phone":      "03-1234-5678",
				"PostalCode": "100-0001",
				"CreditCard": "4111-1111-1111-1111",
			}
			for piiType, expectedValue := range expectedPII {
				found := false
				for _, finding := range res.PIIFindings {
					if finding.Type == piiType && finding.Value == expectedValue {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected PII type %s with value %s was not detected", piiType, expectedValue)
				}
			}
		case ts.URL + "/about":
			if res.Broken {
				t.Errorf("/about should not be broken")
			}
		case ts.URL + "/about/team":
			if res.Broken {
				t.Errorf("/about/team should not be broken")
			}
		case ts.URL + "/broken":
			if !res.Broken {
				t.Errorf("/broken should be marked as broken")
			}
			if res.StatusCode != 404 {
				t.Errorf("/broken expected status 404, got %d", res.StatusCode)
			}
		case "https://example.com/external":
			// external link should be checked (or attempt to check).
			// Depending on network capability in sandbox, we just check if it was processed.
			t.Logf("External URL result: broken=%v, error=%v", res.Broken, res.Error)
		}
	}
}
