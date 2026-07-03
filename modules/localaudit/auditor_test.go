package localaudit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAuditor_Audit(t *testing.T) {
	// Create a temporary directory for audit tests
	tempDir, err := os.MkdirTemp("", "local_audit_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Write a file with AWS Access Key and db_password (CIS-3.12)
	envContent := `
# Environment config
PORT=8080
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DB_PASSWORD="my-super-secret-password-123"
`
	err = os.WriteFile(filepath.Join(tempDir, ".env"), []byte(envContent), 0644)
	if err != nil {
		t.Fatalf("failed to write test env file: %v", err)
	}

	// 2. Write a backup file (CIS-4.7)
	err = os.WriteFile(filepath.Join(tempDir, "database.sql.bak"), []byte("select 1;"), 0644)
	if err != nil {
		t.Fatalf("failed to write test backup file: %v", err)
	}

	// 3. Write sshd_config with insecure settings (CIS-4.1 / CIS-4.8)
	sshConfigContent := `
Protocol 1
PermitRootLogin yes
PasswordAuthentication yes
`
	err = os.WriteFile(filepath.Join(tempDir, "sshd_config"), []byte(sshConfigContent), 0644)
	if err != nil {
		t.Fatalf("failed to write test sshd_config: %v", err)
	}

	// 4. Write sysctl.conf with insecure settings (CIS-4.1)
	sysctlContent := `
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 1
`
	err = os.WriteFile(filepath.Join(tempDir, "sysctl.conf"), []byte(sysctlContent), 0644)
	if err != nil {
		t.Fatalf("failed to write test sysctl.conf: %v", err)
	}

	// 5. Test permissions on Unix platforms (CIS-3.14)
	if runtime.GOOS != "windows" {
		// Private key file with loose permissions
		keyPath := filepath.Join(tempDir, "test.key")
		err = os.WriteFile(keyPath, []byte("-----BEGIN RSA PRIVATE KEY-----\nMOCK\n-----END RSA PRIVATE KEY-----"), 0666) // Readable & writable by anyone
		if err != nil {
			t.Fatalf("failed to write test key file: %v", err)
		}
	}

	// Run audit
	auditor := NewAuditor()
	results, err := auditor.Audit(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}

	// Assert results
	findingsMap := make(map[string]int)
	for _, res := range results {
		findingsMap[res.RuleID]++
	}

	if findingsMap["CIS-3.12"] < 3 {
		t.Errorf("expected at least 3 credentials findings (AWS keys, DB password), got %d", findingsMap["CIS-3.12"])
	}

	if findingsMap["CIS-4.7"] < 1 {
		t.Errorf("expected at least 1 backup/temporary file finding, got %d", findingsMap["CIS-4.7"])
	}

	if findingsMap["CIS-4.1"] < 3 { // SSH Protocol 1, SSH Root Login, Sysctl IP Forwarding
		t.Errorf("expected at least 3 CIS-4.1 findings, got %d", findingsMap["CIS-4.1"])
	}

	if findingsMap["CIS-4.8"] < 1 { // SSH Password Authentication
		t.Errorf("expected at least 1 CIS-4.8 findings, got %d", findingsMap["CIS-4.8"])
	}

	if runtime.GOOS != "windows" {
		if findingsMap["CIS-3.14"] < 2 { // World writable files & Loose permission on key
			t.Errorf("expected at least 2 CIS-3.14 findings on Unix, got %d", findingsMap["CIS-3.14"])
		}
	}
}
