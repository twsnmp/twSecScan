package webscanner

import (
	"net/http"
	"testing"
)

func TestCheckHeaders(t *testing.T) {
	tests := []struct {
		name          string
		targetURL     string
		headers       http.Header
		expectedCount int
		verify        func(t *testing.T, findings []HeaderFinding)
	}{
		{
			name:      "All secure headers missing, no leaks (HTTP)",
			targetURL: "http://example.com",
			headers:   http.Header{},
			// HTTP context: STS is not checked, so CSP, XFO, XCTO, RP, PP missing = 5 findings
			expectedCount: 5,
			verify: func(t *testing.T, findings []HeaderFinding) {
				hasSTS := false
				for _, f := range findings {
					if f.Header == "Strict-Transport-Security" {
						hasSTS = true
					}
				}
				if hasSTS {
					t.Errorf("expected no HSTS finding on HTTP target")
				}
			},
		},
		{
			name:          "All secure headers missing (HTTPS)",
			targetURL:     "https://example.com",
			headers:       http.Header{},
			expectedCount: 6, // HSTS, CSP, XFO, XCTO, RP, PP missing
		},
		{
			name:      "All secure headers present, no leaks",
			targetURL: "https://example.com",
			headers: http.Header{
				"Strict-Transport-Security": []string{"max-age=63072000; includeSubDomains; preload"},
				"Content-Security-Policy":   []string{"default-src 'self'"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
				"Permissions-Policy":        []string{"geolocation=()"},
			},
			expectedCount: 0,
		},
		{
			name:      "Information leaks present",
			targetURL: "https://example.com",
			headers: http.Header{
				"Strict-Transport-Security": []string{"max-age=63072000; includeSubDomains; preload"},
				"Content-Security-Policy":   []string{"default-src 'self'"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
				"Permissions-Policy":        []string{"geolocation=()"},
				"Server":                    []string{"Apache/2.4.41"},
				"X-Powered-By":              []string{"PHP/7.4.3"},
				"X-Aspnet-Version":          []string{"4.0.30319"},
			},
			expectedCount: 3,
			verify: func(t *testing.T, findings []HeaderFinding) {
				foundServer := false
				foundPoweredBy := false
				foundAspNet := false
				for _, f := range findings {
					if f.Header == "Server" && f.Status == "Information Leak" {
						foundServer = true
					}
					if f.Header == "X-Powered-By" && f.Status == "Information Leak" {
						foundPoweredBy = true
					}
					if f.Header == "X-AspNet-Version" && f.Status == "Information Leak" {
						foundAspNet = true
					}
				}
				if !foundServer || !foundPoweredBy || !foundAspNet {
					t.Errorf("expected Server, X-Powered-By, and X-AspNet-Version leaks to be detected")
				}
			},
		},
		{
			name:      "Insecure header settings",
			targetURL: "https://example.com",
			headers: http.Header{
				"Strict-Transport-Security": []string{"max-age=63072000; includeSubDomains; preload"},
				"Content-Security-Policy":   []string{"default-src 'self'"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"sniff-me-please"},
				"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
				"Permissions-Policy":        []string{"geolocation=()"},
			},
			expectedCount: 1,
			verify: func(t *testing.T, findings []HeaderFinding) {
				if len(findings) == 1 && findings[0].Header != "X-Content-Type-Options" {
					t.Errorf("expected X-Content-Type-Options finding, got %s", findings[0].Header)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CheckHeaders(tt.targetURL, tt.headers)
			if len(findings) != tt.expectedCount {
				t.Errorf("expected %d findings, got %d: %+v", tt.expectedCount, len(findings), findings)
			}
			if tt.verify != nil {
				tt.verify(t, findings)
			}
		})
	}
}
