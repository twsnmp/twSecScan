package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"twSecScan/core/models"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketConfig   = []byte("config")
	bucketScans    = []byte("scans")
	bucketFindings = []byte("findings")

	configKey = []byte("system")
)

// DB wraps bbolt DB and provides helper methods for CRUD operations.
type DB struct {
	conn *bolt.DB
}

// NewDB opens the database and initializes buckets.
func NewDB(dbPath string) (*DB, error) {
	conn, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open bbolt db: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.initBuckets(); err != nil {
		conn.Close()
		return nil, err
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

func (db *DB) initBuckets() error {
	return db.conn.Update(func(tx *bolt.Tx) error {
		buckets := [][]byte{bucketConfig, bucketScans, bucketFindings}
		for _, b := range buckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("failed to create bucket %s: %w", b, err)
			}
		}
		return nil
	})
}

// GetConfig retrieves the system configuration.
func (db *DB) GetConfig() (*models.Config, error) {
	var cfg models.Config
	err := db.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketConfig)
		data := b.Get(configKey)
		if data == nil {
			// Return default config if not initialized
			cfg = models.Config{
				OllamaURL:       "http://localhost:11434",
				OllamaModel:     "llama3",
				ActiveProvider:  "ollama",
				ScanConcurrency: 10,
				Language:        "auto",
			}
			return nil
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
		if cfg.Language == "" {
			cfg.Language = "auto"
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveConfig saves the system configuration.
func (db *DB) SaveConfig(cfg *models.Config) error {
	return db.conn.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketConfig)
		data, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return b.Put(configKey, data)
	})
}

// SaveScan saves a scan record.
func (db *DB) SaveScan(scan *models.Scan) error {
	if scan.ID == "" {
		return fmt.Errorf("scan ID cannot be empty")
	}
	return db.conn.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketScans)
		data, err := json.Marshal(scan)
		if err != nil {
			return err
		}
		return b.Put([]byte(scan.ID), data)
	})
}

// GetScan retrieves a scan record by ID.
func (db *DB) GetScan(scanID string) (*models.Scan, error) {
	var scan models.Scan
	err := db.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketScans)
		data := b.Get([]byte(scanID))
		if data == nil {
			return fmt.Errorf("scan not found: %s", scanID)
		}
		return json.Unmarshal(data, &scan)
	})
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// ListScans retrieves all scans sorted by StartTime descending.
func (db *DB) ListScans() ([]*models.Scan, error) {
	scans := []*models.Scan{}
	err := db.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketScans)
		return b.ForEach(func(k, v []byte) error {
			var scan models.Scan
			if err := json.Unmarshal(v, &scan); err != nil {
				return err
			}
			scans = append(scans, &scan)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// Sort scans by StartTime descending (newest first)
	for i := 0; i < len(scans); i++ {
		for j := i + 1; j < len(scans); j++ {
			if scans[i].StartTime.Before(scans[j].StartTime) {
				scans[i], scans[j] = scans[j], scans[i]
			}
		}
	}

	return scans, nil
}

// DeleteScan deletes a scan record and all associated findings.
func (db *DB) DeleteScan(scanID string) error {
	return db.conn.Update(func(tx *bolt.Tx) error {
		// Delete findings first
		bf := tx.Bucket(bucketFindings)
		c := bf.Cursor()
		prefix := []byte(scanID + ":")
		for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Next() {
			if err := bf.Delete(k); err != nil {
				return err
			}
		}

		// Delete scan record
		bs := tx.Bucket(bucketScans)
		return bs.Delete([]byte(scanID))
	})
}

// SaveFinding saves a scan finding. The key in findings bucket is "scanID:findingID".
func (db *DB) SaveFinding(finding *models.Finding) error {
	if finding.ID == "" || finding.ScanID == "" {
		return fmt.Errorf("finding ID and ScanID cannot be empty")
	}
	return db.conn.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFindings)
		data, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		key := []byte(finding.ScanID + ":" + finding.ID)
		return b.Put(key, data)
	})
}

// ListFindingsByScan retrieves all findings associated with a specific scan ID.
func (db *DB) ListFindingsByScan(scanID string) ([]*models.Finding, error) {
	var findings []*models.Finding
	err := db.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFindings)
		c := b.Cursor()
		prefix := []byte(scanID + ":")
		for k, v := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, v = c.Next() {
			var finding models.Finding
			if err := json.Unmarshal(v, &finding); err != nil {
				return err
			}
			findings = append(findings, &finding)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}
