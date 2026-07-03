package webscanner_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"twSecScan/modules/webscanner"
)

func TestTechDetector_Start(t *testing.T) {
	// Set up mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			// Set Nginx server header and PHP powered-by header, and contain React script in body
			w.Header().Set("Server", "nginx/1.18.0")
			w.Header().Set("X-Powered-By", "PHP/7.4.3")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body><div id=\"root\">React App</div><script src=\"react.production.min.js\"></script></body></html>"))
		case "/wp-login.php":
			// Simulate WordPress login page probing
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	detector := webscanner.NewTechDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resultsChan, err := detector.Start(ctx, ts.URL, webscanner.TechDetectorOptions{
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to start tech detector: %v", err)
	}

	detectedNames := make(map[string]bool)
	for res := range resultsChan {
		detectedNames[res.Name] = true
	}

	expectedTechs := []string{"Nginx", "PHP", "React", "WordPress"}
	for _, tech := range expectedTechs {
		if !detectedNames[tech] {
			t.Errorf("Expected to detect technology: %s", tech)
		}
	}
}
