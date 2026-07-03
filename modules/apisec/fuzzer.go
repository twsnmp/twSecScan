package apisec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// APIFuzzResult represents a result of a single fuzzing test case
type APIFuzzResult struct {
	URL               string        `json:"url"`
	Method            string        `json:"method"`
	Parameter         string        `json:"parameter"`
	Payload           string        `json:"payload"`
	VulnerabilityType string        `json:"vulnerabilityType"` // "SQLi", "XSS", "BoundaryValue", "TypeMismatch"
	Severity          string        `json:"severity"`          // "info", "low", "medium", "high", "critical"
	Proof             string        `json:"proof"`
	StatusCode        int           `json:"statusCode"`
	Duration          time.Duration `json:"duration"`
	Vulnerable        bool          `json:"vulnerable"`
}

// APIFuzzOptions configures the API fuzzer
type APIFuzzOptions struct {
	Concurrency int           `json:"concurrency"`
	Timeout     time.Duration `json:"timeout"`
	Delay       time.Duration `json:"delay"`
	UserAgent   string        `json:"userAgent"`
	BaseURL     string        `json:"baseUrl"` // Target API Base URL (e.g. http://localhost:8081)
}

// FuzzPayload defines a test string and its metadata
type FuzzPayload struct {
	Value string
	Type  string // "SQLi", "XSS", "BoundaryValue", "TypeMismatch"
}

// Default fuzzer payloads
var DefaultAPIPayloads = []FuzzPayload{
	// SQL Injection
	{Value: "'", Type: "SQLi"},
	{Value: "1' OR '1'='1", Type: "SQLi"},
	{Value: "UNION SELECT NULL", Type: "SQLi"},

	// XSS
	{Value: "<script>alert(1)</script>", Type: "XSS"},
	{Value: "\"><img src=x onerror=alert(1)>", Type: "XSS"},

	// Boundary Value (Large input)
	{Value: strings.Repeat("A", 10000), Type: "BoundaryValue"},

	// Type Mismatch (e.g. sending a string to an integer parameter)
	{Value: "not_an_integer", Type: "TypeMismatch"},
}

// Database error signatures
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

// APIFuzzer performs automated fuzzing on API endpoints
type APIFuzzer struct {
	httpClient *http.Client
}

// NewAPIFuzzer creates a new APIFuzzer instance
func NewAPIFuzzer() *APIFuzzer {
	return &APIFuzzer{}
}

type fuzzJob struct {
	endpoint APIEndpoint
	param    string
	paramIn  string // "query", "path", "body"
	payload  FuzzPayload
}

// Start runs fuzzing tests concurrently against target endpoints extracted from spec
func (f *APIFuzzer) Start(ctx context.Context, endpoints []APIEndpoint, opts APIFuzzOptions) (<-chan APIFuzzResult, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	f.httpClient = &http.Client{
		Timeout: timeout,
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	baseURL := strings.TrimSuffix(opts.BaseURL, "/")

	// Generate jobs
	var jobs []fuzzJob
	for _, ep := range endpoints {
		// Fuzz Query Parameters
		for _, qp := range ep.QueryParams {
			// Select matching payloads
			for _, payload := range DefaultAPIPayloads {
				// Only test TypeMismatch if parameter type is integer/number
				if payload.Type == "TypeMismatch" && qp.Type != "integer" && qp.Type != "number" {
					continue
				}
				jobs = append(jobs, fuzzJob{
					endpoint: ep,
					param:    qp.Name,
					paramIn:  "query",
					payload:  payload,
				})
			}
		}

		// Fuzz Path Parameters
		for _, pp := range ep.PathParams {
			for _, payload := range DefaultAPIPayloads {
				if payload.Type == "TypeMismatch" && pp.Type != "integer" && pp.Type != "number" {
					continue
				}
				// Skip very long strings for path parameters to avoid HTTP 414 URI Too Long errors
				if payload.Type == "BoundaryValue" {
					continue
				}
				jobs = append(jobs, fuzzJob{
					endpoint: ep,
					param:    pp.Name,
					paramIn:  "path",
					payload:  payload,
				})
			}
		}

		// Fuzz JSON Request Body Properties
		if ep.RequestBody != nil && ep.RequestBody.Properties != nil {
			for propName, propVal := range ep.RequestBody.Properties {
				for _, payload := range DefaultAPIPayloads {
					if payload.Type == "TypeMismatch" && propVal.Type != "integer" && propVal.Type != "number" {
						continue
					}
					jobs = append(jobs, fuzzJob{
						endpoint: ep,
						param:    propName,
						paramIn:  "body",
						payload:  payload,
					})
				}
			}
		}
	}

	resultsChan := make(chan APIFuzzResult, 100)
	jobsChan := make(chan fuzzJob, len(jobs))

	// Queue the jobs
	for _, job := range jobs {
		jobsChan <- job
	}
	close(jobsChan)

	var wg sync.WaitGroup

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
					result := f.testJob(ctx, job, baseURL, opts.UserAgent)
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

func (f *APIFuzzer) testJob(ctx context.Context, job fuzzJob, baseURL, userAgent string) APIFuzzResult {
	result := APIFuzzResult{
		Method:            job.endpoint.Method,
		Parameter:         job.param,
		Payload:           job.payload.Value,
		VulnerabilityType: job.payload.Type,
		Vulnerable:        false,
	}

	// Prepare URL path (replacing path parameters)
	pathStr := job.endpoint.Path
	for _, pp := range job.endpoint.PathParams {
		val := "test_val"
		if pp.Name == job.param && job.paramIn == "path" {
			val = job.payload.Value
		} else if pp.Type == "integer" {
			val = "1"
		}
		pathStr = strings.ReplaceAll(pathStr, "{"+pp.Name+"}", url.PathEscape(val))
	}

	testURL := baseURL + pathStr

	// Prepare Query parameters
	queryParams := url.Values{}
	for _, qp := range job.endpoint.QueryParams {
		val := "test_val"
		if qp.Name == job.param && job.paramIn == "query" {
			val = job.payload.Value
		} else if qp.Type == "integer" {
			val = "1"
		}
		queryParams.Set(qp.Name, val)
	}

	if len(queryParams) > 0 {
		testURL += "?" + queryParams.Encode()
	}

	result.URL = testURL

	// Prepare request body (JSON)
	var bodyReader io.Reader
	if job.endpoint.Method == http.MethodPost || job.endpoint.Method == http.MethodPut || job.endpoint.Method == http.MethodPatch {
		if job.endpoint.RequestBody != nil && job.endpoint.RequestBody.Properties != nil {
			bodyMap := make(map[string]interface{})
			for propName, propVal := range job.endpoint.RequestBody.Properties {
				var val interface{} = "test_val"
				if propName == job.param && job.paramIn == "body" {
					if job.payload.Type == "TypeMismatch" {
						val = job.payload.Value // Send string to numeric property
					} else {
						val = job.payload.Value
					}
				} else if propVal.Type == "integer" {
					val = 1
				}
				bodyMap[propName] = val
			}

			jsonBytes, err := json.Marshal(bodyMap)
			if err == nil {
				bodyReader = bytes.NewReader(jsonBytes)
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, job.endpoint.Method, testURL, bodyReader)
	if err != nil {
		return result
	}

	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := f.httpClient.Do(req)
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

	// Analyze response
	f.analyzeResponse(resp.StatusCode, bodyStr, job.payload, &result)

	return result
}

func (f *APIFuzzer) analyzeResponse(statusCode int, bodyStr string, payload FuzzPayload, result *APIFuzzResult) {
	lowerBody := strings.ToLower(bodyStr)

	// 1. SQL Injection check (Error based SQLi)
	if payload.Type == "SQLi" {
		for _, sig := range SQLiSignatures {
			if strings.Contains(lowerBody, sig) {
				result.Vulnerable = true
				result.Severity = "critical"
				result.Proof = fmt.Sprintf("SQL injection signature found in response: %q", sig)
				return
			}
		}

		if statusCode == http.StatusInternalServerError {
			result.Vulnerable = true
			result.Severity = "high"
			result.Proof = "SQL injection payload caused HTTP 500 Internal Server Error"
			return
		}
	}

	// 2. XSS check
	if payload.Type == "XSS" {
		if strings.Contains(bodyStr, payload.Value) {
			result.Vulnerable = true
			result.Severity = "high"
			result.Proof = fmt.Sprintf("XSS payload reflected directly in response body: %s", payload.Value)
			return
		}
	}

	// 3. Boundary Value Check (Server failures / unhandled crashes on large inputs)
	if payload.Type == "BoundaryValue" {
		if statusCode == http.StatusInternalServerError {
			result.Vulnerable = true
			result.Severity = "medium"
			result.Proof = "Large string payload caused HTTP 500 Internal Server Error (potential buffer overflow or unhandled input validation error)"
			return
		}
	}

	// 4. Type Mismatch Check
	if payload.Type == "TypeMismatch" {
		if statusCode == http.StatusInternalServerError {
			result.Vulnerable = true
			result.Severity = "medium"
			result.Proof = "Type mismatch payload caused HTTP 500 Internal Server Error instead of clean validation response (e.g. 400 Bad Request)"
			return
		}
	}
}
