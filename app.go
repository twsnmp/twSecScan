package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"twSecScan/core/db"
	"twSecScan/core/models"
	"twSecScan/embed"
	"twSecScan/modules/ai"
	"twSecScan/modules/osint"
	"twSecScan/modules/webscanner"
)

// App struct
type App struct {
	ctx      context.Context
	wailsCtx context.Context
	database *db.DB
	mu       sync.Mutex
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
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
func (a *App) StartScan(target string, scanType string) (*models.Scan, error) {
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

	// Resolve host to ensure we can connect
	_, err := net.LookupHost(scan.Target)
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

