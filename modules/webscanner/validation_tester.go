package webscanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ValidationResult represents a security finding or test result for a query parameter.
type ValidationResult struct {
	URL               string        `json:"url"`
	Parameter         string        `json:"parameter"`
	Payload           string        `json:"payload"`
	VulnerabilityType string        `json:"vulnerabilityType"` // "SQLi" or "XSS"
	Severity          string        `json:"severity"`          // "high", "medium", "low"
	Proof             string        `json:"proof"`
	StatusCode        int           `json:"statusCode"`
	Duration          time.Duration `json:"duration"`
	Vulnerable        bool          `json:"vulnerable"`
}

// ValidationOptions configures the input validation tester.
type ValidationOptions struct {
	Concurrency int           `json:"concurrency"`
	Timeout     time.Duration `json:"timeout"`
	Delay       time.Duration `json:"delay"`
	UserAgent   string        `json:"userAgent"`
}

// Payload defines a test string and its associated vulnerability type.
type Payload struct {
	Value string
	Type  string // "SQLi" or "XSS"
}

// SQLi and XSS payloads to test validation behavior.
var DefaultPayloads = []Payload{
	// SQL Injection payloads
	{Value: "'", Type: "SQLi"},
	{Value: "1' OR '1'='1", Type: "SQLi"},
	{Value: "\"", Type: "SQLi"},
	{Value: "1\" OR \"1\"=\"1", Type: "SQLi"},
	{Value: "UNION SELECT NULL", Type: "SQLi"},

	// XSS payloads
	{Value: "<script>alert(1)</script>", Type: "XSS"},
	{Value: "\"><script>alert(1)</script>", Type: "XSS"},
	{Value: "\"><img src=x onerror=alert(1)>", Type: "XSS"},
}

// SQLi database error signatures
var SQLiSignatures = []string{
	"sql syntax",
	"mysql",
	"sqlite",
	"postgresql",
	"oracle",
	"database error",
	"syntax error",
	"unclosed quotation mark",
	"sqlstate",
}

// ValidationTester checks parameters for input validation issues.
type ValidationTester struct {
	httpClient *http.Client
}

// NewValidationTester creates a new ValidationTester instance.
func NewValidationTester() *ValidationTester {
	return &ValidationTester{}
}

type validationJob struct {
	targetURL string
	param     string
	payload   Payload
}

// Start runs the validation tests concurrently and streams findings to the returned channel.
func (vt *ValidationTester) Start(ctx context.Context, targetURLs []string, opts ValidationOptions) (<-chan ValidationResult, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	vt.httpClient = &http.Client{
		Timeout: timeout,
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	// Generate all jobs
	var jobs []validationJob
	for _, target := range targetURLs {
		parsed, err := url.Parse(target)
		if err != nil {
			continue
		}
		query := parsed.Query()
		if len(query) == 0 {
			continue
		}

		for param := range query {
			for _, payload := range DefaultPayloads {
				jobs = append(jobs, validationJob{
					targetURL: target,
					param:     param,
					payload:   payload,
				})
			}
		}
	}

	resultsChan := make(chan ValidationResult, 100)
	jobsChan := make(chan validationJob, len(jobs))

	// Queue the jobs
	for _, job := range jobs {
		jobsChan <- job
	}
	close(jobsChan)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobsChan:
					if !ok {
						return
					}

					startTime := time.Now()
					result := vt.testJob(ctx, job, opts.UserAgent)
					result.Duration = time.Since(startTime)

					if result.Vulnerable {
						select {
						case resultsChan <- result:
						case <-ctx.Done():
							return
						}
					}

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

	// Wait and close results channel
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	return resultsChan, nil
}

func (vt *ValidationTester) testJob(ctx context.Context, job validationJob, userAgent string) ValidationResult {
	result := ValidationResult{
		URL:               job.targetURL,
		Parameter:         job.param,
		Payload:           job.payload.Value,
		VulnerabilityType: job.payload.Type,
		Vulnerable:        false,
	}

	parsed, err := url.Parse(job.targetURL)
	if err != nil {
		return result
	}

	// Inject payload into the parameter
	query := parsed.Query()
	query.Set(job.param, job.payload.Value)
	parsed.RawQuery = query.Encode()
	testURL := parsed.String()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return result
	}

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := vt.httpClient.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}
	bodyStr := string(bodyBytes)

	// Detection logic based on payload type
	if job.payload.Type == "XSS" {
		// If payload is reflected exactly in the body, it means there is a lack of HTML encoding.
		if strings.Contains(bodyStr, job.payload.Value) {
			result.Vulnerable = true
			result.Severity = "high"
			result.Proof = fmt.Sprintf("XSS payload reflected directly in response: %s", job.payload.Value)
		}
	} else if job.payload.Type == "SQLi" {
		// 1. Check for database error strings in the body
		lowerBody := strings.ToLower(bodyStr)
		for _, sig := range SQLiSignatures {
			if strings.Contains(lowerBody, sig) {
				result.Vulnerable = true
				result.Severity = "critical"
				result.Proof = fmt.Sprintf("Database error signature found in body: %q", sig)
				break
			}
		}

		// 2. Check if HTTP Status Code is 500 Internal Server Error when injecting SQLi payloads
		if !result.Vulnerable && resp.StatusCode == http.StatusInternalServerError {
			result.Vulnerable = true
			result.Severity = "high"
			result.Proof = "Injected payload resulted in HTTP 500 Internal Server Error (potential SQLi or unhandled database exception)"
		}
	}

	return result
}
