package webscanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TechSignature defines matching criteria for a web technology.
type TechSignature struct {
	Name         string
	Category     string
	Headers      map[string]string // Header Name -> Substring value
	HTMLContains []string          // All strings must match in the HTML body
	ProbePaths   []string          // Relative paths to check. If any returns status 200, this signature is matched.
}

// TechResult is the detection output.
type TechResult struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	MatchedBy   string `json:"matchedBy"`
}

// TechDetector Options
type TechDetectorOptions struct {
	Timeout   time.Duration
	UserAgent string
}

// TechDetector analyzes a target website for tech stack detection.
type TechDetector struct {
	httpClient *http.Client
}

// NewTechDetector creates a new TechDetector.
func NewTechDetector() *TechDetector {
	return &TechDetector{}
}

// DefaultSignatures defines a list of technologies we want to detect.
var DefaultSignatures = []TechSignature{
	{
		Name:     "WordPress",
		Category: "CMS",
		Headers: map[string]string{
			"X-Pingback": "xmlrpc.php",
		},
		HTMLContains: []string{"wp-content/"},
		ProbePaths:   []string{"/wp-login.php", "/wp-admin/"},
	},
	{
		Name:     "Drupal",
		Category: "CMS",
		Headers: map[string]string{
			"X-Generator": "Drupal",
		},
		HTMLContains: []string{"sites/default/files"},
		ProbePaths:   []string{"/robots.txt"}, // can check if it has drupal paths, but directory checks are safer.
	},
	{
		Name:     "Next.js",
		Category: "Framework",
		HTMLContains: []string{"_next/static", "id=\"__next\""},
	},
	{
		Name:     "React",
		Category: "Frontend Library",
		HTMLContains: []string{"data-reactroot", "react.development.js", "react.production.min.js"},
	},
	{
		Name:     "Vue.js",
		Category: "Frontend Library",
		HTMLContains: []string{"data-v-", "v-cloak", "vue.js", "vue.runtime.js"},
	},
	{
		Name:     "Nginx",
		Category: "Web Server",
		Headers: map[string]string{
			"Server": "nginx",
		},
	},
	{
		Name:     "Apache",
		Category: "Web Server",
		Headers: map[string]string{
			"Server": "apache",
		},
	},
	{
		Name:     "Microsoft IIS",
		Category: "Web Server",
		Headers: map[string]string{
			"Server": "microsoft-iis",
		},
	},
	{
		Name:     "PHP",
		Category: "Programming Language",
		Headers: map[string]string{
			"X-Powered-By": "php",
			"Set-Cookie":   "PHPSESSID",
		},
	},
	{
		Name:     "Express",
		Category: "Framework",
		Headers: map[string]string{
			"X-Powered-By": "express",
		},
	},
	{
		Name:     "Django",
		Category: "Framework",
		Headers: map[string]string{
			"Set-Cookie": "csrftoken",
		},
		HTMLContains: []string{"csrfmiddlewaretoken"},
	},
}

// Start initiates the technology detection scan.
func (td *TechDetector) Start(ctx context.Context, targetURLStr string, opts TechDetectorOptions) (<-chan TechResult, error) {
	parsedURL, err := url.Parse(targetURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if td.httpClient == nil {
		td.httpClient = &http.Client{
			Timeout: opts.Timeout,
		}
	}

	resultsChan := make(chan TechResult)

	go func() {
		defer close(resultsChan)

		// 1. Fetch base URL
		req, err := http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
		if err != nil {
			return
		}
		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		}

		resp, err := td.httpClient.Do(req)
		var headers http.Header
		var htmlBody string
		if err == nil {
			headers = resp.Header
			bodyBytes, _ := io.ReadAll(resp.Body)
			htmlBody = string(bodyBytes)
			resp.Body.Close()
		}

		// Keep track of detected technologies to avoid duplicates
		detected := make(map[string]bool)

		// Helper to push detection result
		emitMatch := func(sig TechSignature, matchedBy string) {
			if !detected[sig.Name] {
				detected[sig.Name] = true
				desc := fmt.Sprintf("Detected %s (%s) via %s", sig.Name, sig.Category, matchedBy)
				select {
				case <-ctx.Done():
					return
				case resultsChan <- TechResult{
					Name:        sig.Name,
					Category:    sig.Category,
					Description: desc,
					MatchedBy:   matchedBy,
				}:
				}
			}
		}

		// 2. Perform signature checking on base URL headers & HTML body
		for _, sig := range DefaultSignatures {
			// Header matching
			if headers != nil {
				for hName, hValSub := range sig.Headers {
					val := headers.Get(hName)
					if val != "" && strings.Contains(strings.ToLower(val), strings.ToLower(hValSub)) {
						emitMatch(sig, fmt.Sprintf("header:%s (%s)", hName, val))
					}
				}
			}

			// HTML body matching
			if htmlBody != "" && len(sig.HTMLContains) > 0 {
				matchedAny := false
				for _, matchStr := range sig.HTMLContains {
					if strings.Contains(htmlBody, matchStr) {
						matchedAny = true
						break
					}
				}
				if matchedAny {
					emitMatch(sig, "HTML signature match")
				}
			}
		}

		// 3. Perform path probing for remaining undetected signatures
		for _, sig := range DefaultSignatures {
			if detected[sig.Name] || len(sig.ProbePaths) == 0 {
				continue
			}

			for _, relPath := range sig.ProbePaths {
				probeURL, err := parsedURL.Parse(relPath)
				if err != nil {
					continue
				}

				req, err := http.NewRequestWithContext(ctx, "GET", probeURL.String(), nil)
				if err != nil {
					continue
				}
				if opts.UserAgent != "" {
					req.Header.Set("User-Agent", opts.UserAgent)
				}

				resp, err := td.httpClient.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()

				// If 200 OK or 403 Forbidden (often means admin page exists but restricted), consider it a signal.
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
					emitMatch(sig, fmt.Sprintf("probe:%s (Status %d)", relPath, resp.StatusCode))
					break
				}
			}
		}
	}()

	return resultsChan, nil
}
