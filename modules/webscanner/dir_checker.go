package webscanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuditResult represents the result of checking a specific path.
type AuditResult struct {
	Path       string        `json:"path"`
	URL        string        `json:"url"`
	StatusCode int           `json:"statusCode"`
	Error      string        `json:"error"`
	Severity   string        `json:"severity"`
	Exposed    bool          `json:"exposed"`
	Duration   time.Duration `json:"duration"`
}

// AuditOptions configures the Asset Auditor.
type AuditOptions struct {
	Concurrency int           `json:"concurrency"`
	Timeout     time.Duration `json:"timeout"`
	Delay       time.Duration `json:"delay"` // Delay between requests in worker
}

// AssetAuditor checks a target for exposed files/directories.
type AssetAuditor struct {
	httpClient *http.Client
}

// NewAssetAuditor creates a new AssetAuditor instance.
func NewAssetAuditor() *AssetAuditor {
	return &AssetAuditor{}
}

// Start initiates the directory checking process concurrently.
// It returns a channel where findings are reported.
func (a *AssetAuditor) Start(ctx context.Context, baseURLStr string, paths []string, opts AuditOptions) (<-chan AuditResult, error) {
	parsedBaseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	a.httpClient = &http.Client{
		Timeout: timeout,
		// Do not automatically follow redirects, to accurately capture 301/302 vs 200/403
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	resultsChan := make(chan AuditResult, 100)
	pathsChan := make(chan string, len(paths))

	// Populate the paths to check
	for _, p := range paths {
		pathsChan <- p
	}
	close(pathsChan)

	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case path, ok := <-pathsChan:
					if !ok {
						return
					}

					// Build request URL
					reqURL := buildAuditURL(parsedBaseURL, path)
					
					startTime := time.Now()
					result := a.checkPath(ctx, reqURL, path)
					result.Duration = time.Since(startTime)

					select {
					case resultsChan <- result:
					case <-ctx.Done():
						return
					}

					// Apply delay/wait if configured
					if opts.Delay > 0 {
						select {
						case <-time.After(opts.Delay):
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	// Close the results channel when all workers are done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	return resultsChan, nil
}

func (a *AssetAuditor) checkPath(ctx context.Context, targetURL, rawPath string) AuditResult {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return AuditResult{
			Path:    rawPath,
			URL:     targetURL,
			Error:   err.Error(),
			Exposed: false,
		}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return AuditResult{
			Path:    rawPath,
			URL:     targetURL,
			Error:   err.Error(),
			Exposed: false,
		}
	}
	defer resp.Body.Close()

	// An asset is considered exposed if we receive a 200 OK or 403 Forbidden
	// (403 indicates the folder/file exists but access is forbidden, confirming its presence).
	exposed := resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden

	severity := "info"
	if exposed {
		// Determine severity based on critical files
		lowerPath := strings.ToLower(rawPath)
		if strings.Contains(lowerPath, ".env") || strings.Contains(lowerPath, "config.php") || strings.Contains(lowerPath, "config.json") || strings.Contains(lowerPath, "private") {
			severity = "critical"
		} else if strings.Contains(lowerPath, "backup") || strings.Contains(lowerPath, ".git") || strings.Contains(lowerPath, "db") || strings.Contains(lowerPath, "database") {
			severity = "high"
		} else if strings.Contains(lowerPath, "admin") || strings.Contains(lowerPath, "console") || strings.Contains(lowerPath, "dashboard") {
			severity = "medium"
		} else {
			severity = "low"
		}
	}

	return AuditResult{
		Path:       rawPath,
		URL:        targetURL,
		StatusCode: resp.StatusCode,
		Exposed:    exposed,
		Severity:   severity,
	}
}

func buildAuditURL(baseURL *url.URL, path string) string {
	u := *baseURL
	// Clear any fragment or query parameters from base URL
	u.RawQuery = ""
	u.Fragment = ""

	basePath := u.Path
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	
	// Strip leading slash from path to prevent duplicate slashes
	cleanPath := strings.TrimPrefix(path, "/")
	u.Path = basePath + cleanPath

	return u.String()
}
