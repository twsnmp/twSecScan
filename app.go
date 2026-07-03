package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"twSecScan/core/db"
	"twSecScan/core/models"
	"twSecScan/embed"
	"twSecScan/modules/ai"
	"twSecScan/modules/apisec"
	"twSecScan/modules/osint"
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
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		testServer: webscanner.NewTestServer(),
	}
}

// startup is called when the app starts. The context is saved
// and we initialize the bbolt database.
func (a *App) startup(ctx context.Context) {
	a.wailsCtx = ctx
	dbPath := "twSecScan.db"
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
		desc := "DNS query completed successfully. Retreived DNS records configuration."
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

	scan.Status = "completed"
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


