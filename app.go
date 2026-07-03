package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"twSecScan/core/db"
	"twSecScan/core/models"
	"twSecScan/modules/ai"
	"twSecScan/modules/osint"
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

// StartScan triggers a port scan asynchronously
func (a *App) StartScan(target string) (*models.Scan, error) {
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

	// Run scan in the background
	go a.runScanJob(scan, cfg)

	return scan, nil
}

func (a *App) runScanJob(scan *models.Scan, cfg *models.Config) {
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
