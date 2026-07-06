package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"twSecScan/core/db"
	"twSecScan/core/models"
	"twSecScan/embed"
	"twSecScan/modules/ai"
	"twSecScan/modules/apisec"
	"twSecScan/modules/osint"
	"twSecScan/modules/localaudit"
	"twSecScan/modules/webscanner"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx        context.Context
	wailsCtx   context.Context
	database   *db.DB
	mu         sync.Mutex
	testServer *webscanner.TestServer
	dbPath     string // resolved database file path
	version    string // application version (set at build time via ldflags)
}

// NewApp creates a new App application struct.
// dbPath overrides the default database location when non-empty.
// version is the application version string embedded at build time.
func NewApp(dbPath, version string) *App {
	return &App{
		testServer: webscanner.NewTestServer(),
		dbPath:     dbPath,
		version:    version,
	}
}

// GetVersion returns the application version string.
// The version is embedded at build time via -ldflags "-X main.version=..."
// and includes the Git tag and short commit hash (e.g. "v1.2.0-abc1234").
func (a *App) GetVersion() string {
	return a.version
}

// getDataPath returns the platform-appropriate path for a data file.
//
//	macOS:   ~/Library/Application Support/twSecScan/<filename>
//	Windows: %APPDATA%\twSecScan\<filename>
//	Linux:   ~/.config/twSecScan/<filename>
//
// If override is non-empty, it is used as-is.
func getDataPath(override, filename string) (string, error) {
	if override != "" {
		return override, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config dir: %w", err)
	}
	appDir := filepath.Join(configDir, "twSecScan")
	if err := os.MkdirAll(appDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create app data dir %s: %w", appDir, err)
	}
	return filepath.Join(appDir, filename), nil
}

// startup is called when the app starts. The context is saved
// and we initialize the bbolt database.
func (a *App) startup(ctx context.Context) {
	a.wailsCtx = ctx
	dbPath, err := getDataPath(a.dbPath, "twSecScan.db")
	if err != nil {
		log.Printf("Failed to resolve database path: %v", err)
		return
	}
	log.Printf("Database path: %s", dbPath)
	database, err := db.NewDB(dbPath)
	if err != nil {
		log.Printf("Failed to initialize database: %v", err)
		return
	}
	a.database = database
}

// shutdown is called when the app closes
func (a *App) shutdown(ctx context.Context) {
	if a.database != nil {
		a.database.Close()
	}
}

// GetConfig retrieves configuration settings
func (a *App) GetConfig() (*models.Config, error) {
	if a.database == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return a.database.GetConfig()
}

// SaveConfig saves configuration settings
func (a *App) SaveConfig(cfg *models.Config) error {
	if a.database == nil {
		return fmt.Errorf("database not initialized")
	}
	return a.database.SaveConfig(cfg)
}

// ListScans lists all scan history
func (a *App) ListScans() ([]*models.Scan, error) {
	if a.database == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return a.database.ListScans()
}

// GetScan retrieves a single scan history entry
func (a *App) GetScan(scanID string) (*models.Scan, error) {
	if a.database == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return a.database.GetScan(scanID)
}

// GetFindings gets findings for a scan ID
func (a *App) GetFindings(scanID string) ([]*models.Finding, error) {
	if a.database == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return a.database.ListFindingsByScan(scanID)
}

// DeleteScan deletes a scan and its findings
func (a *App) DeleteScan(scanID string) error {
	if a.database == nil {
		return fmt.Errorf("database not initialized")
	}
	return a.database.DeleteScan(scanID)
}

// StartScan triggers a vulnerability scan (port scan or web scan) asynchronously
func (a *App) StartScan(target string, scanType string, extra string) (*models.Scan, error) {
	if a.database == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// Basic host validation
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	cfg, err := a.database.GetConfig()
	if err != nil {
		return nil, err
	}

	scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())
	scan := &models.Scan{
		ID:           scanID,
		Target:       target,
		Status:       "running",
		StartTime:    time.Now(),
		FindingCount: make(map[string]int),
	}

	if err := a.database.SaveScan(scan); err != nil {
		return nil, err
	}

	// Run scan in the background depending on type
	if scanType == "webscanner" {
		go a.runWebScan(scan, cfg)
	} else if scanType == "asset_auditor" {
		go a.runAssetAuditScan(scan, cfg)
	} else if scanType == "validation_tester" {
		go a.runValidationTesterScan(scan, cfg)
	} else if scanType == "tech_detector" {
		go a.runTechDetectorScan(scan, cfg)
	} else if scanType == "apisec" {
		go a.runAPISecScan(scan, cfg, extra)
	} else if scanType == "dns_whois" {
		go a.runDNSWhoisScan(scan, cfg)
	} else if scanType == "crypto_scanner" {
		go a.runCryptoScan(scan, cfg)
	} else if scanType == "local_audit" {
		go a.runLocalAuditScan(scan, cfg)
	} else {
		go a.runPortScan(scan, cfg)
	}

	return scan, nil
}

func (a *App) runPortScan(scan *models.Scan, cfg *models.Config) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	// Resolve host to ensure we can connect. If target is a URL or has port details, extract hostname.
	host := scan.Target
	if u, err := url.Parse(scan.Target); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(scan.Target); err == nil {
		host = h
	}

	_, err := net.LookupHost(host)
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("failed to resolve target: %v", err)
		return
	}

	// Ports to scan
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443}
	concurrency := cfg.ScanConcurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	openPorts, err := osint.ScanPorts(ctx, scan.Target, commonPorts, 500*time.Millisecond, concurrency)
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("scan failed or timed out: %v", err)
		return
	}

	// Initialize AI Client if key or server is provided
	var aiClient ai.LLMClient
	if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
		aiClient, _ = ai.NewClient(cfg)
	}

	for _, port := range openPorts {
		findingID := fmt.Sprintf("find_%d_%d", port, time.Now().UnixNano())
		title := fmt.Sprintf("Open Port Detected: %d", port)
		desc := fmt.Sprintf("TCP Port %d is open on target %s. Unused ports should be closed to reduce the attack surface.", port, scan.Target)
		proof := fmt.Sprintf("TCP connection succeeded on port %d.", port)
		severity := "low"

		// Elevate severity for database or sensitive ports
		switch port {
		case 21: // FTP
			severity = "medium"
		case 22: // SSH
			severity = "low"
		case 23: // Telnet
			severity = "high"
		case 445: // SMB
			severity = "high"
		case 1433, 1521, 3306, 5432: // Databases
			severity = "medium"
		}

		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "osint",
			Title:       title,
			Description: desc,
			Severity:    severity,
			Proof:       proof,
			Timestamp:   time.Now(),
		}

		// Perform AI analysis if client is ready
		if aiClient != nil {
			advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
			if err == nil {
				finding.AIAdvice = advice
			} else {
				finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
			}
		} else {
			finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
		}

		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}

		scan.FindingCount[severity]++
	}

	// Also perform DNS & WHOIS checks as part of the OSINT scan
	a.executeDNSWhois(ctx, scan, cfg, host)

	scan.Status = "completed"
}

func (a *App) runWebScan(scan *models.Scan, cfg *models.Config) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	concurrency := cfg.ScanConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	crawler := webscanner.NewCrawler()
	resultsChan, err := crawler.Start(ctx, scan.Target, webscanner.Options{
		Concurrency: concurrency,
		Timeout:     5 * time.Second,
		UserAgent:   "twSecScan-BrokenLinkChecker/1.0",
	})
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("failed to start crawler: %v", err)
		return
	}

	// Initialize AI Client if configured
	var aiClient ai.LLMClient
	if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
		aiClient, _ = ai.NewClient(cfg)
	}

	for res := range resultsChan {
		if res.Broken {
			severity := "medium"
			if !res.Internal {
				severity = "low"
			}

			findingID := fmt.Sprintf("find_link_%d", time.Now().UnixNano())
			title := fmt.Sprintf("Broken Link Detected: %s", res.URL)

			var linkType string
			if res.Internal {
				linkType = "Internal"
			} else {
				linkType = "External"
			}

			var reason string
			if res.StatusCode > 0 {
				reason = fmt.Sprintf("returned HTTP status code %d", res.StatusCode)
			} else if res.Error != "" {
				reason = fmt.Sprintf("failed with error: %s", res.Error)
			} else {
				reason = "failed to fetch"
			}

			desc := fmt.Sprintf("%s link check failed. The URL %s is broken/dead. It %s. Found on page: %s", linkType, res.URL, reason, res.Source)
			proof := fmt.Sprintf("Status Code: %d, Error: %s, Source: %s", res.StatusCode, res.Error, res.Source)

			finding := &models.Finding{
				ID:          findingID,
				ScanID:      scan.ID,
				Target:      scan.Target,
				Module:      "webscanner",
				Title:       title,
				Description: desc,
				Severity:    severity,
				Proof:       proof,
				Timestamp:   time.Now(),
			}

			// Generate AI advice if client is configured
			if aiClient != nil {
				advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
				if err == nil {
					finding.AIAdvice = advice
				} else {
					finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
				}
			} else {
				finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
			}

			if err := a.database.SaveFinding(finding); err != nil {
				log.Printf("Failed to save finding: %v", err)
			}

			scan.FindingCount[severity]++
		}

		// Process HTTP header findings
		for _, hf := range res.HeaderFindings {
			findingID := fmt.Sprintf("find_header_%d", time.Now().UnixNano())
			title := fmt.Sprintf("HTTP Header Issue (%s): %s", hf.Status, hf.Header)
			
			desc := fmt.Sprintf("An HTTP header vulnerability was detected on %s.\nHeader: %s\nStatus: %s\nDescription: %s", 
				res.URL, hf.Header, hf.Status, hf.Description)
			proof := fmt.Sprintf("URL: %s\nFinding Details: %s\nProof: %s", res.URL, hf.Description, hf.Proof)

			finding := &models.Finding{
				ID:          findingID,
				ScanID:      scan.ID,
				Target:      scan.Target,
				Module:      "webscanner",
				Title:       title,
				Description: desc,
				Severity:    hf.Severity,
				Proof:       proof,
				Timestamp:   time.Now(),
			}

			// Generate AI advice if client is configured
			if aiClient != nil {
				advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
				if err == nil {
					finding.AIAdvice = advice
				} else {
					finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
				}
			} else {
				finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
			}

			if err := a.database.SaveFinding(finding); err != nil {
				log.Printf("Failed to save finding: %v", err)
			}

			scan.FindingCount[hf.Severity]++
		}

		// Process PII (Personally Identifiable Information) findings
		for _, pii := range res.PIIFindings {
			severity := "low"
			if pii.Type == "CreditCard" {
				severity = "medium"
			}

			findingID := fmt.Sprintf("find_pii_%d", time.Now().UnixNano())
			title := fmt.Sprintf("PII Exposure Detected (%s): %s", pii.Type, res.URL)
			
			desc := fmt.Sprintf("Personally Identifiable Information (PII) of type '%s' was exposed in the HTML body of %s.\nExposed Value: %s", 
				pii.Type, res.URL, pii.Value)
			proof := fmt.Sprintf("URL: %s\nPII Type: %s\nDetected Value: %s", res.URL, pii.Type, pii.Value)

			finding := &models.Finding{
				ID:          findingID,
				ScanID:      scan.ID,
				Target:      scan.Target,
				Module:      "webscanner",
				Title:       title,
				Description: desc,
				Severity:    severity,
				Proof:       proof,
				Timestamp:   time.Now(),
			}

			// Generate AI advice if client is configured
			if aiClient != nil {
				advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
				if err == nil {
					finding.AIAdvice = advice
				} else {
					finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
				}
			} else {
				finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
			}

			if err := a.database.SaveFinding(finding); err != nil {
				log.Printf("Failed to save finding: %v", err)
			}

			scan.FindingCount[severity]++
		}
	}

	scan.Status = "completed"
}

func (a *App) runAssetAuditScan(scan *models.Scan, cfg *models.Config) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	paths, err := embed.GetDirectoryWordlist()
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("failed to load directory wordlist: %v", err)
		return
	}

	concurrency := cfg.ScanConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	auditor := webscanner.NewAssetAuditor()
	// Set a reasonable request delay to respect target server resources (e.g. 100ms)
	resultsChan, err := auditor.Start(ctx, scan.Target, paths, webscanner.AuditOptions{
		Concurrency: concurrency,
		Timeout:     5 * time.Second,
		Delay:       100 * time.Millisecond,
	})
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("failed to start asset auditor: %v", err)
		return
	}

	// Initialize AI Client if configured
	var aiClient ai.LLMClient
	if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
		aiClient, _ = ai.NewClient(cfg)
	}

	for res := range resultsChan {
		if res.Exposed {
			findingID := fmt.Sprintf("find_audit_%d", time.Now().UnixNano())
			title := fmt.Sprintf("Exposed Configuration or Asset: %s", res.Path)

			var details string
			if res.StatusCode == http.StatusOK {
				details = "The path is publicly accessible (HTTP 200 OK), which might expose sensitive data, backups, or system directories."
			} else if res.StatusCode == http.StatusForbidden {
				details = "Access to the path is forbidden (HTTP 403 Forbidden). While direct access is blocked, its existence is confirmed, which can assist attackers in mapping the directory structure."
			} else {
				details = fmt.Sprintf("The path returned HTTP status code %d.", res.StatusCode)
			}

			desc := fmt.Sprintf("Asset auditing detected an exposed directory or file resource. Path: %s. URL: %s. Details: %s", res.Path, res.URL, details)
			proof := fmt.Sprintf("Path: %s, Status Code: %d", res.Path, res.StatusCode)

			finding := &models.Finding{
				ID:          findingID,
				ScanID:      scan.ID,
				Target:      scan.Target,
				Module:      "asset_auditor",
				Title:       title,
				Description: desc,
				Severity:    res.Severity,
				Proof:       proof,
				Timestamp:   time.Now(),
			}

			// Generate AI advice if client is configured
			if aiClient != nil {
				advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
				if err == nil {
					finding.AIAdvice = advice
				} else {
					finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
				}
			} else {
				finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
			}

			if err := a.database.SaveFinding(finding); err != nil {
				log.Printf("Failed to save finding: %v", err)
			}

			scan.FindingCount[res.Severity]++
		}
	}

	scan.Status = "completed"
}

func (a *App) runValidationTesterScan(scan *models.Scan, cfg *models.Config) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	concurrency := cfg.ScanConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// 1. Run crawler to discover URLs
	crawler := webscanner.NewCrawler()
	resultsChan, err := crawler.Start(ctx, scan.Target, webscanner.Options{
		Concurrency: concurrency,
		Timeout:     5 * time.Second,
		UserAgent:   "twSecScan-ValidationCrawler/1.0",
	})
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("failed to start crawler: %v", err)
		return
	}

	var urlsToTest []string
	// Include the start URL itself
	urlsToTest = append(urlsToTest, scan.Target)

	for res := range resultsChan {
		// Collect unique successfully visited internal URLs
		if !res.Broken && res.Internal {
			urlsToTest = append(urlsToTest, res.URL)
		}
	}

	// Remove duplicates
	uniqueURLs := make(map[string]bool)
	var finalURLs []string
	for _, u := range urlsToTest {
		if !uniqueURLs[u] {
			uniqueURLs[u] = true
			finalURLs = append(finalURLs, u)
		}
	}

	// 2. Run ValidationTester on discovered URLs
	tester := webscanner.NewValidationTester()
	valResultsChan, err := tester.Start(ctx, finalURLs, webscanner.ValidationOptions{
		Concurrency: concurrency,
		Timeout:     5 * time.Second,
		UserAgent:   "twSecScan-ValidationTester/1.0",
	})
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("failed to start validation tester: %v", err)
		return
	}

	// Initialize AI Client if configured
	var aiClient ai.LLMClient
	if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
		aiClient, _ = ai.NewClient(cfg)
	}

	for res := range valResultsChan {
		if res.Vulnerable {
			findingID := fmt.Sprintf("find_val_%d", time.Now().UnixNano())
			title := fmt.Sprintf("Input Validation Vulnerability (%s): %s", res.VulnerabilityType, res.Parameter)
			
			desc := fmt.Sprintf("A potential %s vulnerability was detected on parameter '%s' of URL %s. The payload '%s' resulted in lack of sanitization or error exposure.", 
				res.VulnerabilityType, res.Parameter, res.URL, res.Payload)
			
			finding := &models.Finding{
				ID:          findingID,
				ScanID:      scan.ID,
				Target:      scan.Target,
				Module:      "validation_tester",
				Title:       title,
				Description: desc,
				Severity:    res.Severity,
				Proof:       res.Proof,
				Timestamp:   time.Now(),
			}

			// Generate AI advice if client is configured
			if aiClient != nil {
				advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
				if err == nil {
					finding.AIAdvice = advice
				} else {
					finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
				}
			} else {
				finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
			}

			if err := a.database.SaveFinding(finding); err != nil {
				log.Printf("Failed to save finding: %v", err)
			}

			scan.FindingCount[res.Severity]++
		}
	}

	scan.Status = "completed"
}

// runAPISecScan implements parsing OpenAPI specifications and running API fuzzing
func (a *App) runAPISecScan(scan *models.Scan, cfg *models.Config, customBaseURL string) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// 1. Parse OpenAPI Spec
	doc, err := apisec.LoadOpenAPISpec(ctx, scan.Target)
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("Failed to load OpenAPI Spec: %v", err)
		return
	}

	endpoints := apisec.ExtractEndpoints(doc)
	if len(endpoints) == 0 {
		scan.Status = "failed"
		scan.ErrorMsg = "No endpoints extracted from OpenAPI spec"
		return
	}

	// 2. Determine base URL
	baseURL := ""
	if customBaseURL != "" {
		baseURL = customBaseURL
	} else {
		if len(doc.Servers) > 0 && doc.Servers[0].URL != "" {
			baseURL = doc.Servers[0].URL
		}
		
		// If scan.Target is a URL, we can also extract its base URL
		if strings.HasPrefix(scan.Target, "http://") || strings.HasPrefix(scan.Target, "https://") {
			u, err := url.Parse(scan.Target)
			if err == nil {
				// e.g. http://localhost:8081/openapi.json -> http://localhost:8081
				baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
			}
		}

		if baseURL == "" {
			baseURL = "http://localhost:8080" // fallback
		}
	}

	concurrency := cfg.ScanConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	// 3. Start Fuzzer
	fuzzer := apisec.NewAPIFuzzer()
	resultsChan, err := fuzzer.Start(ctx, endpoints, apisec.APIFuzzOptions{
		Concurrency: concurrency,
		Timeout:     5 * time.Second,
		BaseURL:     baseURL,
		UserAgent:   "twSecScan-APISecurityScanner/1.0",
	})
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("Failed to start API fuzzer: %v", err)
		return
	}

	// Initialize AI Client if configured
	var aiClient ai.LLMClient
	if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
		aiClient, _ = ai.NewClient(cfg)
	}

	for res := range resultsChan {
		if res.Vulnerable {
			findingID := fmt.Sprintf("find_api_%d", time.Now().UnixNano())
			title := fmt.Sprintf("API Vulnerability (%s): %s %s", res.VulnerabilityType, res.Method, res.Parameter)
			desc := fmt.Sprintf("A potential %s vulnerability was detected on parameter '%s' of API path %s %s. Payload: '%s'",
				res.VulnerabilityType, res.Parameter, res.Method, res.URL, res.Payload)

			finding := &models.Finding{
				ID:          findingID,
				ScanID:      scan.ID,
				Target:      scan.Target,
				Module:      "apisec",
				Title:       title,
				Description: desc,
				Severity:    res.Severity,
				Proof:       res.Proof,
				Timestamp:   time.Now(),
			}

			if aiClient != nil {
				advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
				if err == nil {
					finding.AIAdvice = advice
				} else {
					finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
				}
			} else {
				finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
			}

			if err := a.database.SaveFinding(finding); err != nil {
				log.Printf("Failed to save finding: %v", err)
			}

			scan.FindingCount[res.Severity]++
		}
	}

	scan.Status = "completed"
}

func (a *App) runDNSWhoisScan(scan *models.Scan, cfg *models.Config) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	host := scan.Target
	if u, err := url.Parse(scan.Target); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(scan.Target); err == nil {
		host = h
	}

	a.executeDNSWhois(ctx, scan, cfg, host)
	scan.Status = "completed"
}

func (a *App) executeDNSWhois(ctx context.Context, scan *models.Scan, cfg *models.Config, host string) {
	// 1. DNS Lookup
	dnsRecords, err := osint.LookupDNS(ctx, host)
	if err == nil {
		var detailLines []string
		if len(dnsRecords.A) > 0 {
			detailLines = append(detailLines, fmt.Sprintf("A Records: %s", strings.Join(dnsRecords.A, ", ")))
		}
		if len(dnsRecords.AAAA) > 0 {
			detailLines = append(detailLines, fmt.Sprintf("AAAA Records: %s", strings.Join(dnsRecords.AAAA, ", ")))
		}
		if len(dnsRecords.MX) > 0 {
			detailLines = append(detailLines, fmt.Sprintf("MX Records: %s", strings.Join(dnsRecords.MX, ", ")))
		}
		if len(dnsRecords.TXT) > 0 {
			detailLines = append(detailLines, fmt.Sprintf("TXT Records: %s", strings.Join(dnsRecords.TXT, ", ")))
		}
		if len(dnsRecords.NS) > 0 {
			detailLines = append(detailLines, fmt.Sprintf("NS Records: %s", strings.Join(dnsRecords.NS, ", ")))
		}
		if dnsRecords.CNAME != "" {
			detailLines = append(detailLines, fmt.Sprintf("CNAME Record: %s", dnsRecords.CNAME))
		}

		findingID := fmt.Sprintf("find_dns_%d", time.Now().UnixNano())
		title := fmt.Sprintf("DNS Records for %s", host)
		desc := "DNS query completed successfully. Retrieved DNS records configuration."
		proof := strings.Join(detailLines, " | ")
		if proof == "" {
			proof = "No DNS records resolved."
		}

		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "dns_whois",
			Title:       title,
			Description: desc,
			Severity:    "info",
			Proof:       proof,
			Timestamp:   time.Now(),
		}

		// Initialize AI Client if configured
		var aiClient ai.LLMClient
		if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
			aiClient, _ = ai.NewClient(cfg)
		}

		if aiClient != nil {
			advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
			if err == nil {
				finding.AIAdvice = advice
			} else {
				finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
			}
		} else {
			finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
		}

		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}
		scan.FindingCount["info"]++
	} else {
		log.Printf("DNS Lookup failed: %v", err)
	}

	// 2. WHOIS Lookup
	whoisRaw, err := osint.QueryWHOIS(ctx, host)
	if err == nil {
		findingID := fmt.Sprintf("find_whois_%d", time.Now().UnixNano())
		title := fmt.Sprintf("WHOIS Information for %s", host)
		desc := "WHOIS registration lookup completed successfully."
		proof := whoisRaw
		if len(proof) > 4000 {
			proof = proof[:4000] + "\n... [Truncated due to size]"
		}

		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "dns_whois",
			Title:       title,
			Description: desc,
			Severity:    "info",
			Proof:       proof,
			Timestamp:   time.Now(),
		}

		// Initialize AI Client if configured
		var aiClient ai.LLMClient
		if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
			aiClient, _ = ai.NewClient(cfg)
		}

		if aiClient != nil {
			// Ask AI to analyze whois raw data
			advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
			if err == nil {
				finding.AIAdvice = advice
			} else {
				finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
			}
		} else {
			finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
		}

		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}
		scan.FindingCount["info"]++
	} else {
		log.Printf("WHOIS Lookup failed: %v", err)
	}
}

// SelectOpenAPISpecFile shows a file selector dialog to choose an OpenAPI definition file (JSON or YAML)
func (a *App) SelectOpenAPISpecFile() (string, error) {
	if a.wailsCtx == nil {
		return "", fmt.Errorf("Wails context not initialized")
	}

	return wailsruntime.OpenFileDialog(a.wailsCtx, wailsruntime.OpenDialogOptions{
		Title: "Select OpenAPI Specification File",
		Filters: []wailsruntime.FileFilter{
			{
				DisplayName: "OpenAPI Files (*.json, *.yaml, *.yml)",
				Pattern:     "*.json;*.yaml;*.yml",
			},
		},
	})
}

// ToggleTestServer handles starting and stopping the local mock vulnerability server.
func (a *App) ToggleTestServer(enable bool) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.testServer == nil {
		a.testServer = webscanner.NewTestServer()
	}

	if enable {
		addr, err := a.testServer.Start()
		if err != nil {
			return "", err
		}
		return addr, nil
	} else {
		err := a.testServer.Stop()
		if err != nil {
			return "", err
		}
		return "", nil
	}
}

func (a *App) runTechDetectorScan(scan *models.Scan, cfg *models.Config) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	concurrency := cfg.ScanConcurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	detector := webscanner.NewTechDetector()
	resultsChan, err := detector.Start(ctx, scan.Target, webscanner.TechDetectorOptions{
		Timeout:   5 * time.Second,
		UserAgent: "twSecScan-TechDetector/1.0",
	})
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("failed to start tech detector: %v", err)
		return
	}

	// Initialize AI Client if configured
	var aiClient ai.LLMClient
	if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
		aiClient, _ = ai.NewClient(cfg)
	}

	var detectedList []string
	var proofBuilder strings.Builder

	for res := range resultsChan {
		detectedList = append(detectedList, fmt.Sprintf("%s (%s)", res.Name, res.Category))
		proofBuilder.WriteString(fmt.Sprintf("- %s: %s\n", res.Name, res.Description))
	}

	if len(detectedList) > 0 {
		findingID := fmt.Sprintf("find_tech_%d", time.Now().UnixNano())
		title := "Detected Technology Stack (Web Fingerprint)"
		desc := fmt.Sprintf("The following technologies were detected on the target website:\n%s", strings.Join(detectedList, ", "))
		proof := proofBuilder.String()

		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "tech_detector",
			Title:       title,
			Description: desc,
			Severity:    "info",
			Proof:       proof,
			Timestamp:   time.Now(),
		}

		if aiClient != nil {
			advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
			if err == nil {
				finding.AIAdvice = advice
			} else {
				finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
			}
		} else {
			finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
		}

		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}

		scan.FindingCount["info"]++
	} else {
		findingID := fmt.Sprintf("find_tech_%d", time.Now().UnixNano())
		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "tech_detector",
			Title:       "No Recognized Technologies Detected",
			Description: "The technology detector scan completed, but no signatures matched the target website. This could mean the server headers are customized/hidden, or it uses less common technologies.",
			Severity:    "info",
			Proof:       "All signatures returned negative match.",
			Timestamp:   time.Now(),
			AIAdvice:    "No specific actions required. Obfuscating server headers is a good security practice to hinder automated reconnaissance.",
		}

		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}
		scan.FindingCount["info"]++
	}

	scan.Status = "completed"
}

func (a *App) runCryptoScan(scan *models.Scan, cfg *models.Config) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	host := scan.Target
	if u, err := url.Parse(scan.Target); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(scan.Target); err == nil {
		host = h
	}

	scanner := osint.NewCryptoScanner(5 * time.Second)
	results, err := scanner.Scan(ctx, host)
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("Failed to run crypto scanner: %v", err)
		return
	}

	// Initialize AI Client if configured
	var aiClient ai.LLMClient
	if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
		aiClient, _ = ai.NewClient(cfg)
	}

	for _, res := range results {
		findingID := fmt.Sprintf("find_crypto_%d_%d", res.Port, time.Now().UnixNano())
		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "crypto_scanner",
			Title:       res.Title,
			Description: res.Description,
			Severity:    res.Severity,
			Proof:       res.Proof,
			Timestamp:   time.Now(),
		}

		if aiClient != nil {
			advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
			if err == nil {
				finding.AIAdvice = advice
			} else {
				finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
			}
		} else {
			finding.AIAdvice = "AI analysis not configured. Set up Ollama/OpenAI/Anthropic in Settings."
		}

		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}
		scan.FindingCount[res.Severity]++
	}

	if len(results) == 0 {
		// Log informative finding that no obvious issues were detected
		findingID := fmt.Sprintf("find_crypto_none_%d", time.Now().UnixNano())
		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "crypto_scanner",
			Title:       "Crypto configuration checks passed",
			Description: "Scanned HTTPS, SSH, and mail server ports for encryption settings. No deprecated protocols or invalid certificates were detected.",
			Severity:    "info",
			Proof:       "Scanned ports returned standard results.",
			Timestamp:   time.Now(),
			AIAdvice:    "Continue keeping your certificates renewed and outdated SSL/TLS versions disabled.",
		}
		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}
		scan.FindingCount["info"]++
	}

	scan.Status = "completed"
}

// SelectLocalFolder shows a folder selector dialog to choose a local directory for folder audit
func (a *App) SelectLocalFolder() (string, error) {
	if a.wailsCtx == nil {
		return "", fmt.Errorf("Wails context not initialized")
	}

	return wailsruntime.OpenDirectoryDialog(a.wailsCtx, wailsruntime.OpenDialogOptions{
		Title: "Select Folder for Local Audit",
	})
}

// runLocalAuditScan performs a local audit on the specified directory path
func (a *App) runLocalAuditScan(scan *models.Scan, cfg *models.Config) {
	defer func() {
		scan.EndTime = time.Now()
		if err := a.database.SaveScan(scan); err != nil {
			log.Printf("Failed to save final scan status: %v", err)
		}
	}()

	// Verify target exists and is a directory
	info, err := os.Stat(scan.Target)
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("target directory does not exist: %v", err)
		return
	}
	if !info.IsDir() {
		scan.Status = "failed"
		scan.ErrorMsg = "target path is not a directory"
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	auditor := localaudit.NewAuditor()
	results, err := auditor.Audit(ctx, scan.Target)
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = fmt.Sprintf("audit scan failed: %v", err)
		return
	}

	// Initialize AI Client if configured
	var aiClient ai.LLMClient
	if cfg.ActiveProvider == "ollama" || cfg.APIKeyOpenAI != "" || cfg.APIKeyAnthropic != "" {
		aiClient, _ = ai.NewClient(cfg)
	}

	for _, res := range results {
		findingID := fmt.Sprintf("find_localaudit_%d", time.Now().UnixNano())
		title := fmt.Sprintf("[%s] %s", res.RuleID, res.Title)

		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "local_audit",
			Title:       title,
			Description: fmt.Sprintf("File: %s\nRule: %s\n\n%s", res.FilePath, res.RuleID, res.Description),
			Severity:    res.Severity,
			Proof:       res.Proof,
			Timestamp:   time.Now(),
		}

		// Generate AI advice if client is configured
		if aiClient != nil {
			advice, err := aiClient.AnalyzeFinding(ctx, finding.Target, finding.Title, finding.Description, finding.Proof)
			if err == nil {
				finding.AIAdvice = advice
			} else {
				finding.AIAdvice = fmt.Sprintf("AI advice generation failed: %v", err)
			}
		} else {
			finding.AIAdvice = "AI mitigation advice not configured. Set up Ollama/OpenAI/Anthropic in Settings."
		}

		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}
		scan.FindingCount[res.Severity]++
	}

	if len(results) == 0 {
		findingID := fmt.Sprintf("find_localaudit_none_%d", time.Now().UnixNano())
		finding := &models.Finding{
			ID:          findingID,
			ScanID:      scan.ID,
			Target:      scan.Target,
			Module:      "local_audit",
			Title:       "Local folder audit passed",
			Description: "No critical credential exposures, insecure configuration files, or suspicious permissions were detected during the local folder walk.",
			Severity:    "info",
			Proof:       "Folder walk completed without findings.",
			Timestamp:   time.Now(),
			AIAdvice:    "Keep applying secure configuration and data protection standards.",
		}
		if err := a.database.SaveFinding(finding); err != nil {
			log.Printf("Failed to save finding: %v", err)
		}
		scan.FindingCount["info"]++
	}

	scan.Status = "completed"
}

// ExportScanReport allows the user to export a report of a scan to a file (HTML, Markdown or JSON)
func (a *App) ExportScanReport(scanID string) (string, error) {
	if a.database == nil {
		return "", fmt.Errorf("database not initialized")
	}
	if a.wailsCtx == nil {
		return "", fmt.Errorf("Wails context not initialized")
	}

	scan, err := a.database.GetScan(scanID)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve scan: %v", err)
	}
	findings, err := a.database.ListFindingsByScan(scanID)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve findings: %v", err)
	}

	cfg, err := a.database.GetConfig()
	lang := "en"
	if err == nil {
		lang = cfg.Language
	}

	// Default filename
	defaultName := fmt.Sprintf("scan_report_%s.html", scan.ID)

	filePath, err := wailsruntime.SaveFileDialog(a.wailsCtx, wailsruntime.SaveDialogOptions{
		Title:           "Export Scan Report",
		DefaultFilename: defaultName,
		Filters: []wailsruntime.FileFilter{
			{
				DisplayName: "HTML Report (*.html)",
				Pattern:     "*.html",
			},
			{
				DisplayName: "Markdown Report (*.md)",
				Pattern:     "*.md",
			},
			{
				DisplayName: "JSON Report (*.json)",
				Pattern:     "*.json",
			},
		},
	})
	if err != nil {
		return "", err
	}
	if filePath == "" {
		return "", nil // cancelled
	}

	var content []byte
	if strings.HasSuffix(strings.ToLower(filePath), ".html") {
		content, err = a.generateHTMLReport(scan, findings, lang)
		if err != nil {
			return "", fmt.Errorf("failed to generate HTML report: %v", err)
		}
	} else if strings.HasSuffix(strings.ToLower(filePath), ".md") {
		content = a.generateMarkdownReport(scan, findings, lang)
	} else {
		// JSON
		type ExportData struct {
			Scan     *models.Scan      `json:"scan"`
			Findings []*models.Finding `json:"findings"`
		}
		data := ExportData{
			Scan:     scan,
			Findings: findings,
		}
		content, err = json.MarshalIndent(data, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON: %v", err)
		}
	}

	err = os.WriteFile(filePath, content, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	return filePath, nil
}

func (a *App) generateMarkdownReport(scan *models.Scan, findings []*models.Finding, lang string) []byte {
	var sb strings.Builder

	titleText := "Security Scan Report"
	targetText := "Target"
	statusText := "Status"
	startTimeText := "Start Time"
	endTimeText := "End Time"
	durationText := "Duration"
	summaryText := "Scan Summary"
	findingsText := "Findings"
	severityText := "Severity"
	moduleText := "Module"
	descText := "Description"
	proofText := "Proof"
	aiAdviceText := "AI Advice"
	noFindingsText := "No findings detected."

	if lang == "ja" {
		titleText = "セキュリティスキャンレポート"
		targetText = "対象"
		statusText = "ステータス"
		startTimeText = "開始日時"
		endTimeText = "終了日時"
		durationText = "所要時間"
		summaryText = "スキャン概要"
		findingsText = "検出結果"
		severityText = "危険度"
		moduleText = "モジュール"
		descText = "詳細説明"
		proofText = "証跡"
		aiAdviceText = "AIアドバイス"
		noFindingsText = "検出された問題はありません。"
	}

	sb.WriteString(fmt.Sprintf("# %s\n\n", titleText))
	sb.WriteString(fmt.Sprintf("## %s\n\n", summaryText))
	sb.WriteString(fmt.Sprintf("- **%s:** `%s`\n", targetText, scan.Target))
	sb.WriteString(fmt.Sprintf("- **Scan ID:** `%s`\n", scan.ID))
	sb.WriteString(fmt.Sprintf("- **%s:** `%s`\n", statusText, scan.Status))
	sb.WriteString(fmt.Sprintf("- **%s:** %s\n", startTimeText, scan.StartTime.Format("2006-01-02 15:04:05")))
	if !scan.EndTime.IsZero() {
		sb.WriteString(fmt.Sprintf("- **%s:** %s\n", endTimeText, scan.EndTime.Format("2006-01-02 15:04:05")))
		duration := scan.EndTime.Sub(scan.StartTime).Round(time.Second)
		sb.WriteString(fmt.Sprintf("- **%s:** %s\n", durationText, duration.String()))
	}
	sb.WriteString("\n")

	sb.WriteString("### Severity Counts\n\n")
	sb.WriteString("| Critical | High | Medium | Low | Info |\n")
	sb.WriteString("| :---: | :---: | :---: | :---: | :---: |\n")
	sb.WriteString(fmt.Sprintf("| %d | %d | %d | %d | %d |\n\n",
		scan.FindingCount["critical"],
		scan.FindingCount["high"],
		scan.FindingCount["medium"],
		scan.FindingCount["low"],
		scan.FindingCount["info"],
	))

	sb.WriteString(fmt.Sprintf("## %s\n\n", findingsText))
	if len(findings) == 0 {
		sb.WriteString(fmt.Sprintf("%s\n", noFindingsText))
	} else {
		for i, f := range findings {
			sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
			sb.WriteString(fmt.Sprintf("- **%s:** `%s`\n", severityText, strings.ToUpper(f.Severity)))
			sb.WriteString(fmt.Sprintf("- **%s:** `%s`\n", moduleText, f.Module))
			sb.WriteString(fmt.Sprintf("- **Timestamp:** %s\n\n", f.Timestamp.Format("2006-01-02 15:04:05")))
			sb.WriteString(fmt.Sprintf("#### %s\n%s\n\n", descText, f.Description))
			if f.Proof != "" {
				sb.WriteString(fmt.Sprintf("#### %s\n```\n%s\n```\n\n", proofText, f.Proof))
			}
			if f.AIAdvice != "" {
				sb.WriteString(fmt.Sprintf("#### %s\n%s\n\n", aiAdviceText, f.AIAdvice))
			}
			sb.WriteString("---\n\n")
		}
	}

	return []byte(sb.String())
}

func (a *App) generateHTMLReport(scan *models.Scan, findings []*models.Finding, lang string) ([]byte, error) {
	titleText := "Security Scan Report"
	targetText := "Target"
	statusText := "Status"
	startTimeText := "Start Time"
	endTimeText := "End Time"
	durationText := "Duration"
	summaryText := "Scan Summary"
	findingsText := "Findings"
	severityText := "Severity"
	moduleText := "Module"
	descText := "Description"
	proofText := "Proof"
	aiAdviceText := "AI Mitigation Advice"
	noFindingsText := "No findings detected."

	if lang == "ja" {
		titleText = "セキュリティスキャンレポート"
		targetText = "対象"
		statusText = "ステータス"
		startTimeText = "開始日時"
		endTimeText = "終了日時"
		durationText = "所要時間"
		summaryText = "スキャン概要"
		findingsText = "検出結果"
		severityText = "危険度"
		moduleText = "モジュール"
		descText = "詳細説明"
		proofText = "証跡"
		aiAdviceText = "AIによる対策方法"
		noFindingsText = "検出された問題はありません。"
	}

	durationStr := ""
	if !scan.EndTime.IsZero() {
		durationStr = scan.EndTime.Sub(scan.StartTime).Round(time.Second).String()
	}

	data := HTMLReportData{
		Lang:           lang,
		Title:          titleText,
		Scan:           scan,
		Findings:       findings,
		StartTimeStr:   scan.StartTime.Format("2006-01-02 15:04:05"),
		EndTimeStr:     scan.EndTime.Format("2006-01-02 15:04:05"),
		DurationStr:    durationStr,
		SummaryText:    summaryText,
		TargetText:     targetText,
		StatusText:     statusText,
		StartTimeText:  startTimeText,
		EndTimeText:    endTimeText,
		DurationText:   durationText,
		FindingsText:   findingsText,
		SeverityText:   severityText,
		ModuleText:     moduleText,
		DescText:       descText,
		ProofText:      proofText,
		AiAdviceText:   aiAdviceText,
		NoFindingsText: noFindingsText,
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type HTMLReportData struct {
	Lang           string
	Title          string
	Scan           *models.Scan
	Findings       []*models.Finding
	StartTimeStr   string
	EndTimeStr     string
	DurationStr    string
	SummaryText    string
	TargetText     string
	StatusText     string
	StartTimeText  string
	EndTimeText    string
	DurationText   string
	FindingsText   string
	SeverityText   string
	ModuleText     string
	DescText       string
	ProofText      string
	AiAdviceText   string
	NoFindingsText string
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="{{.Lang}}">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>{{.Title}}</title>
	<style>
		:root {
			--bg-color: #0f172a;
			--panel-bg: #1e293b;
			--text-color: #f8fafc;
			--text-muted: #94a3b8;
			--border-color: #334155;
			--primary: #6366f1;
			--success: #10b981;
			--danger: #ef4444;
			--warning: #f59e0b;
			--info: #3b82f6;
		}
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			background-color: var(--bg-color);
			color: var(--text-color);
			margin: 0;
			padding: 2rem 1rem;
			line-height: 1.5;
		}
		.container {
			max-width: 1000px;
			margin: 0 auto;
		}
		header {
			border-bottom: 1px solid var(--border-color);
			padding-bottom: 1.5rem;
			margin-bottom: 2rem;
		}
		h1 {
			font-size: 2.25rem;
			font-weight: 800;
			margin: 0 0 0.5rem 0;
			background: linear-gradient(to right, #818cf8, #c084fc);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}
		.subtitle {
			color: var(--text-muted);
			margin: 0;
			font-size: 0.875rem;
		}
		.summary-card {
			background-color: var(--panel-bg);
			border: 1px solid var(--border-color);
			border-radius: 1rem;
			padding: 1.5rem;
			margin-bottom: 2rem;
			box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
		}
		.summary-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
			gap: 1.25rem;
			margin-bottom: 1.5rem;
		}
		.summary-item {
			display: flex;
			flex-direction: column;
		}
		.summary-label {
			font-size: 0.75rem;
			color: var(--text-muted);
			text-transform: uppercase;
			letter-spacing: 0.05em;
			font-weight: 600;
		}
		.summary-value {
			font-size: 1.125rem;
			font-weight: 600;
			margin-top: 0.25rem;
			word-break: break-all;
		}
		.severity-counts {
			display: flex;
			gap: 0.5rem;
			flex-wrap: wrap;
			margin-top: 1rem;
			padding-top: 1rem;
			border-top: 1px solid var(--border-color);
		}
		.badge {
			font-size: 0.75rem;
			font-weight: 700;
			padding: 0.25rem 0.75rem;
			border-radius: 9999px;
			text-transform: uppercase;
		}
		.badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
		.badge-high { background-color: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
		.badge-medium { background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
		.badge-low { background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
		.badge-info { background-color: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.4); }
		.badge-success { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
		
		.finding-card {
			background-color: var(--panel-bg);
			border: 1px solid var(--border-color);
			border-radius: 1rem;
			padding: 1.5rem;
			margin-bottom: 1.5rem;
			box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
			border-left: 4px solid var(--border-color);
		}
		.finding-card.critical { border-left-color: var(--danger); }
		.finding-card.high { border-left-color: var(--warning); }
		.finding-card.medium { border-left-color: #f59e0b; }
		.finding-card.low { border-left-color: var(--info); }
		.finding-card.info { border-left-color: var(--text-muted); }

		.finding-header {
			display: flex;
			justify-content: space-between;
			align-items: flex-start;
			gap: 1rem;
			margin-bottom: 1rem;
		}
		.finding-title {
			font-size: 1.25rem;
			font-weight: 700;
			margin: 0;
		}
		.finding-meta {
			font-size: 0.875rem;
			color: var(--text-muted);
			margin-bottom: 1rem;
		}
		.finding-desc {
			margin-bottom: 1rem;
			white-space: pre-wrap;
		}
		.finding-proof {
			background-color: #0f172a;
			border: 1px solid var(--border-color);
			border-radius: 0.5rem;
			padding: 0.75rem 1rem;
			font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
			font-size: 0.875rem;
			color: #cbd5e1;
			white-space: pre-wrap;
			margin-bottom: 1rem;
		}
		.ai-advice {
			background-color: rgba(99, 102, 241, 0.05);
			border: 1px solid rgba(99, 102, 241, 0.2);
			border-radius: 0.5rem;
			padding: 1rem;
			margin-top: 1rem;
		}
		.ai-advice-header {
			display: flex;
			align-items: center;
			gap: 0.5rem;
			color: #818cf8;
			font-weight: 600;
			font-size: 0.875rem;
			margin-bottom: 0.5rem;
		}
		.ai-advice-content {
			font-size: 0.875rem;
			color: #cbd5e1;
		}
		.ai-advice-content.fallback {
			white-space: pre-wrap;
		}
		.ai-advice-content p {
			margin-top: 0;
			margin-bottom: 0.75rem;
		}
		.ai-advice-content ul, .ai-advice-content ol {
			margin-top: 0;
			margin-bottom: 0.75rem;
			padding-left: 1.25rem;
		}
		.ai-advice-content li {
			margin-bottom: 0.25rem;
		}
		.ai-advice-content code {
			background-color: rgba(255, 255, 255, 0.1);
			padding: 0.1rem 0.3rem;
			border-radius: 0.25rem;
			font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
			font-size: 0.85em;
		}
		.ai-advice-content pre {
			background-color: #0f172a;
			border: 1px solid var(--border-color);
			border-radius: 0.5rem;
			padding: 0.75rem 1rem;
			overflow-x: auto;
		}
		.ai-advice-content pre code {
			background-color: transparent;
			padding: 0;
			border-radius: 0;
		}
		.no-findings {
			text-align: center;
			padding: 3rem;
			color: var(--text-muted);
		}
	</style>
</head>
<body>
	<div class="container">
		<header>
			<h1>{{.Title}}</h1>
			<p class="subtitle">twSecScan - generated on {{.StartTimeStr}}</p>
		</header>

		<div class="summary-card">
			<div class="summary-grid">
				<div class="summary-item">
					<span class="summary-label">{{.TargetText}}</span>
					<span class="summary-value">{{.Scan.Target}}</span>
				</div>
				<div class="summary-item">
					<span class="summary-label">Scan ID</span>
					<span class="summary-value">{{.Scan.ID}}</span>
				</div>
				<div class="summary-item">
					<span class="summary-label">{{.StatusText}}</span>
					<span class="summary-value">{{.Scan.Status}}</span>
				</div>
				<div class="summary-item">
					<span class="summary-label">{{.StartTimeText}}</span>
					<span class="summary-value">{{.StartTimeStr}}</span>
				</div>
				{{if .DurationStr}}
				<div class="summary-item">
					<span class="summary-label">{{.DurationText}}</span>
					<span class="summary-value">{{.DurationStr}}</span>
				</div>
				{{end}}
			</div>

			<div class="severity-counts">
				{{if .Findings}}
					{{range $sev, $count := .Scan.FindingCount}}
						{{if gt $count 0}}
							<span class="badge badge-{{$sev}}">{{$sev}}: {{$count}}</span>
						{{end}}
					{{end}}
				{{else}}
					<span class="badge badge-success">Clean / Safe</span>
				{{end}}
			</div>
		</div>

		<h2>{{.FindingsText}} ({{len .Findings}})</h2>

		<div class="findings-list">
			{{if .Findings}}
				{{range .Findings}}
					<div class="finding-card {{.Severity}}">
						<div class="finding-header">
							<h3 class="finding-title">{{.Title}}</h3>
							<span class="badge badge-{{.Severity}}">{{.Severity}}</span>
						</div>
						<div class="finding-meta">
							Module: <strong>{{.Module}}</strong>
						</div>
						<div class="finding-desc">{{.Description}}</div>
						
						{{if .Proof}}
							<div class="finding-proof"><strong>{{$.ProofText}}:</strong><br>{{.Proof}}</div>
						{{end}}

						{{if .AIAdvice}}
							<div class="ai-advice">
								<div class="ai-advice-header">
									<svg style="width: 16px; height: 16px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path></svg>
									{{$.AiAdviceText}}
								</div>
								<div class="ai-advice-content">{{.AIAdvice}}</div>
							</div>
						{{end}}
					</div>
				{{end}}
			{{else}}
				<div class="no-findings">
					<p>{{.NoFindingsText}}</p>
				</div>
			{{end}}
		</div>
	</div>
	<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
	<script>
		document.addEventListener('DOMContentLoaded', () => {
			document.querySelectorAll('.ai-advice-content').forEach(el => {
				if (typeof marked !== 'undefined') {
					el.innerHTML = marked.parse(el.textContent);
				} else {
					el.classList.add('fallback');
				}
			});
		});
	</script>
</body>
</html>`



