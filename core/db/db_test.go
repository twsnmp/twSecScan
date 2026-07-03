package db

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"twSecScan/core/models"
)

func TestDBOperations(t *testing.T) {
	// Setup temp directory in the workspace
	tmpDir, err := os.MkdirTemp(".", "db_test_")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")

	// 1. NewDB creation
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer db.Close()

	// 2. Test default config
	cfg, err := db.GetConfig()
	if err != nil {
		t.Fatalf("failed to get config: %v", err)
	}
	if cfg.OllamaURL != "http://localhost:11434" {
		t.Errorf("expected default Ollama URL, got %s", cfg.OllamaURL)
	}

	// 3. Test Save & Get Config
	cfg.OllamaURL = "http://localhost:9999"
	cfg.ActiveProvider = "openai"
	if err := db.SaveConfig(cfg); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	cfg2, err := db.GetConfig()
	if err != nil {
		t.Fatalf("failed to get config again: %v", err)
	}
	if cfg2.OllamaURL != "http://localhost:9999" || cfg2.ActiveProvider != "openai" {
		t.Errorf("saved config mismatch: %+v", cfg2)
	}

	// 4. Test Scans
	scan1 := &models.Scan{
		ID:        "scan-1",
		Target:    "example.com",
		Status:    "running",
		StartTime: time.Now().Add(-1 * time.Hour),
	}
	scan2 := &models.Scan{
		ID:        "scan-2",
		Target:    "test.com",
		Status:    "completed",
		StartTime: time.Now(),
	}

	if err := db.SaveScan(scan1); err != nil {
		t.Fatalf("failed to save scan1: %v", err)
	}
	if err := db.SaveScan(scan2); err != nil {
		t.Fatalf("failed to save scan2: %v", err)
	}

	// Get scan
	s, err := db.GetScan("scan-1")
	if err != nil {
		t.Fatalf("failed to get scan-1: %v", err)
	}
	if s.Target != "example.com" {
		t.Errorf("scan target mismatch: %s", s.Target)
	}

	// List scans (should be sorted by StartTime descending, so scan2 then scan1)
	scans, err := db.ListScans()
	if err != nil {
		t.Fatalf("failed to list scans: %v", err)
	}
	if len(scans) != 2 {
		t.Errorf("expected 2 scans, got %d", len(scans))
	}
	if scans[0].ID != "scan-2" || scans[1].ID != "scan-1" {
		t.Errorf("expected sorted scans: scan-2 first, then scan-1. Got order: %s, %s", scans[0].ID, scans[1].ID)
	}

	// 5. Test Findings
	finding1 := &models.Finding{
		ID:        "f-1",
		ScanID:    "scan-1",
		Target:    "example.com",
		Module:    "osint",
		Title:     "Open Port 80",
		Severity:  "info",
		Timestamp: time.Now(),
	}
	finding2 := &models.Finding{
		ID:        "f-2",
		ScanID:    "scan-1",
		Target:    "example.com",
		Module:    "webscanner",
		Title:     "XSS Vulnerability",
		Severity:  "high",
		Timestamp: time.Now(),
	}
	finding3 := &models.Finding{
		ID:        "f-3",
		ScanID:    "scan-2",
		Target:    "test.com",
		Module:    "apisec",
		Title:     "SQLi Vulnerability",
		Severity:  "critical",
		Timestamp: time.Now(),
	}

	if err := db.SaveFinding(finding1); err != nil {
		t.Fatalf("failed to save finding1: %v", err)
	}
	if err := db.SaveFinding(finding2); err != nil {
		t.Fatalf("failed to save finding2: %v", err)
	}
	if err := db.SaveFinding(finding3); err != nil {
		t.Fatalf("failed to save finding3: %v", err)
	}

	// List findings by scan-1
	fList1, err := db.ListFindingsByScan("scan-1")
	if err != nil {
		t.Fatalf("failed to list findings for scan-1: %v", err)
	}
	if len(fList1) != 2 {
		t.Errorf("expected 2 findings for scan-1, got %d", len(fList1))
	}

	// List findings by scan-2
	fList2, err := db.ListFindingsByScan("scan-2")
	if err != nil {
		t.Fatalf("failed to list findings for scan-2: %v", err)
	}
	if len(fList2) != 1 {
		t.Errorf("expected 1 finding for scan-2, got %d", len(fList2))
	}

	// 6. Test Delete Scan and associated findings
	if err := db.DeleteScan("scan-1"); err != nil {
		t.Fatalf("failed to delete scan-1: %v", err)
	}

	// Scan 1 should not exist
	_, err = db.GetScan("scan-1")
	if err == nil {
		t.Errorf("expected error getting deleted scan-1")
	}

	// Findings for scan-1 should be deleted
	fList1Deleted, err := db.ListFindingsByScan("scan-1")
	if err != nil {
		t.Fatalf("failed to list findings for deleted scan-1: %v", err)
	}
	if len(fList1Deleted) != 0 {
		t.Errorf("expected 0 findings for deleted scan-1, got %d", len(fList1Deleted))
	}

	// Scan 2 and its findings should still exist
	_, err = db.GetScan("scan-2")
	if err != nil {
		t.Errorf("expected scan-2 to still exist: %v", err)
	}
	fList2StillExists, err := db.ListFindingsByScan("scan-2")
	if err != nil || len(fList2StillExists) != 1 {
		t.Errorf("expected scan-2 findings to still exist: %v, count: %d", err, len(fList2StillExists))
	}
}
