package localaudit

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// LocalAuditResult represents a single finding during directory audit.
type LocalAuditResult struct {
	FilePath    string `json:"file_path"`
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // "info", "low", "medium", "high", "critical"
	Proof       string `json:"proof"`
}

// Auditor handles directory audits.
type Auditor struct {
	MaxFiles    int
	MaxFileSize int64
}

// NewAuditor returns a configured Auditor.
func NewAuditor() *Auditor {
	return &Auditor{
		MaxFiles:    1000,
		MaxFileSize: 1024 * 1024, // 1MB
	}
}

// Ignored folders and binary extensions
var (
	ignoredDirs = map[string]bool{
		".git":          true,
		"node_modules":  true,
		"vendor":        true,
		"dist":          true,
		"build":         true,
		".svelte-kit":   true,
		".wails":        true,
		".idea":         true,
		".vscode":       true,
		"__pycache__":   true,
	}

	binaryExts = map[string]bool{
		".exe":   true,
		".dll":   true,
		".so":    true,
		".dylib": true,
		".png":   true,
		".jpg":   true,
		".jpeg":  true,
		".gif":   true,
		".ico":   true,
		".pdf":   true,
		".zip":   true,
		".gz":    true,
		".tar":   true,
		".tgz":   true,
		".dmg":   true,
		".pkg":   true,
		".class": true,
		".jar":   true,
		".war":   true,
		".db":    true,
		".sqlite":true,
	}
)

// Regex rules for secrets
var secretRules = []struct {
	name     string
	regex    *regexp.Regexp
	severity string
	desc     string
}{
	{
		name:     "AWS Access Key ID",
		regex:    regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		severity: "high",
		desc:     "AWS Access Key ID was found in plaintext. If exposed, attackers could gain unauthorized access to cloud resources.",
	},
	{
		name:     "Slack Webhook",
		regex:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
		severity: "medium",
		desc:     "A Slack Incoming Webhook URL was found. Attackers could spam your Slack channels or extract workspace info.",
	},
	{
		name:     "Private Key",
		regex:    regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		severity: "critical",
		desc:     "An unencrypted private key block was found. Private keys must be kept secure and never committed to codebase repositories.",
	},
	{
		name:     "Database Connection String Password",
		regex:    regexp.MustCompile(`(?i)(?:db_password|password|db_pass|database_url)\s*[:=]\s*['\"][A-Za-z0-9_\-!@#\$%\^&\*\(\)\+]{4,}['\"]`),
		severity: "medium",
		desc:     "A potential database password or credentials variable assignment was found in plaintext.",
	},
}

// Audit traverses the directory and runs audits on the files.
func (a *Auditor) Audit(ctx context.Context, targetDir string) ([]LocalAuditResult, error) {
	var results []LocalAuditResult
	fileCount := 0

	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories that are in the ignore list
		if d.IsDir() {
			if ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files if we hit the limit
		if fileCount >= a.MaxFiles {
			return filepath.SkipDir
		}

		fileCount++

		// 1. Audit by filename/extension (CIS-4.7: Leftover & Unnecessary Files)
		ext := strings.ToLower(filepath.Ext(path))
		name := d.Name()

		if ext == ".bak" || ext == ".old" || ext == ".temp" || ext == ".tmp" || strings.HasSuffix(name, "~") {
			results = append(results, LocalAuditResult{
				FilePath:    path,
				RuleID:      "CIS-4.7",
				Title:       "Leftover Backup or Temporary File",
				Description: fmt.Sprintf("Backup or temporary file '%s' detected. These files often contain sensitive historical data and should be cleaned up.", name),
				Severity:    "low",
				Proof:       fmt.Sprintf("Filename: %s", name),
			})
		}

		// 2. Audit file permissions (CIS-3.14: Access Control & Permissions)
		info, err := d.Info()
		if err == nil {
			mode := info.Mode()
			// Only apply permission checks on Unix-like OS (Mac and Linux)
			if runtime.GOOS != "windows" {
				// World-writable check (CIS-3.14)
				if mode&0002 != 0 {
					results = append(results, LocalAuditResult{
						FilePath:    path,
						RuleID:      "CIS-3.14",
						Title:       "World-Writable File",
						Description: fmt.Sprintf("The file '%s' has world-writable permissions (%04o). Any local user or system process can modify its contents.", name, mode.Perm()),
						Severity:    "medium",
						Proof:       fmt.Sprintf("Permissions: %04o", mode.Perm()),
					})
				}

				// Loose permission on private keys / environment files
				isSensitiveFile := ext == ".pem" || ext == ".key" || name == "id_rsa" || name == ".env"
				if isSensitiveFile && (mode&0044 != 0) { // Readable by group or others
					results = append(results, LocalAuditResult{
						FilePath:    path,
						RuleID:      "CIS-3.14",
						Title:       "Loose Permissions on Sensitive File",
						Description: fmt.Sprintf("Sensitive file '%s' is readable by group or others (permissions: %04o). It should be restricted to owner-only access (e.g. 0600 or 0400).", name, mode.Perm()),
						Severity:    "high",
						Proof:       fmt.Sprintf("Permissions: %04o", mode.Perm()),
					})
				}

				// Check critical OS files if they are in the target path
				if name == "shadow" && strings.Contains(path, "/etc/") {
					if mode&0044 != 0 {
						results = append(results, LocalAuditResult{
							FilePath:    path,
							RuleID:      "CIS-3.14",
							Title:       "Unsecured Shadow File",
							Description: "The /etc/shadow file containing hashed user passwords has loose read permissions. It must be accessible only by root (0600 or 0000).",
							Severity:    "critical",
							Proof:       fmt.Sprintf("Permissions: %04o", mode.Perm()),
						})
					}
				}
			}
		}

		// 3. Skip binary or oversized files for content scanning
		if binaryExts[ext] || (info != nil && info.Size() > a.MaxFileSize) {
			return nil
		}

		// 4. Content audit
		a.auditFileContent(path, name, &results)

		return nil
	})

	return results, err
}

// auditFileContent reads and scans file content line by line or matches configs
func (a *Auditor) auditFileContent(path string, filename string, results *[]LocalAuditResult) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	// Limit read size to prevent large files from slowing down scans
	reader := io.LimitReader(file, a.MaxFileSize)
	scanner := bufio.NewScanner(reader)

	isSSHConfig := filename == "sshd_config"
	isSysctlConfig := filename == "sysctl.conf"

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// A. Check for secrets
		for _, rule := range secretRules {
			if rule.regex.MatchString(line) {
				// Redact the secret for the proof
				matched := rule.regex.FindString(line)
				redacted := matched
				if len(matched) > 8 {
					redacted = matched[:4] + "..." + matched[len(matched)-4:]
				}

				*results = append(*results, LocalAuditResult{
					FilePath:    path,
					RuleID:      "CIS-3.12",
					Title:       fmt.Sprintf("Hardcoded %s", rule.name),
					Description: rule.desc,
					Severity:    rule.severity,
					Proof:       fmt.Sprintf("Line %d: found secret pattern matching '%s'", lineNum, redacted),
				})
			}
		}

		// B. Check Linux SSH Config (CIS-4.1 / CIS-4.8)
		if isSSHConfig {
			cleanLine := strings.TrimSpace(line)
			if cleanLine != "" && !strings.HasPrefix(cleanLine, "#") {
				parts := strings.Fields(cleanLine)
				if len(parts) >= 2 {
					key := strings.ToLower(parts[0])
					val := strings.ToLower(parts[1])

					if key == "permitrootlogin" && val == "yes" {
						*results = append(*results, LocalAuditResult{
							FilePath:    path,
							RuleID:      "CIS-4.1",
							Title:       "SSH Root Login Enabled",
							Description: "Allowing direct SSH root login increases the risk of brute-force attacks on the root account. It is recommended to set 'PermitRootLogin no' or restrict it to keys-only.",
							Severity:    "high",
							Proof:       fmt.Sprintf("Line %d: PermitRootLogin %s", lineNum, parts[1]),
						})
					}
					if key == "passwordauthentication" && val == "yes" {
						*results = append(*results, LocalAuditResult{
							FilePath:    path,
							RuleID:      "CIS-4.8",
							Title:       "SSH Password Authentication Enabled",
							Description: "Password authentication is active for SSH. Standard practice recommends key-based authentication only to prevent credential brute-forcing.",
							Severity:    "medium",
							Proof:       fmt.Sprintf("Line %d: PasswordAuthentication %s", lineNum, parts[1]),
						})
					}
					if key == "protocol" && val == "1" {
						*results = append(*results, LocalAuditResult{
							FilePath:    path,
							RuleID:      "CIS-4.1",
							Title:       "SSH Protocol 1 Enabled",
							Description: "SSH Protocol 1 contains multiple vulnerability issues and must be disabled in favor of Protocol 2.",
							Severity:    "critical",
							Proof:       fmt.Sprintf("Line %d: Protocol %s", lineNum, parts[1]),
						})
					}
				}
			}
		}

		// C. Check Linux Sysctl Config (CIS-4.1)
		if isSysctlConfig {
			cleanLine := strings.TrimSpace(line)
			if cleanLine != "" && !strings.HasPrefix(cleanLine, "#") {
				if strings.Contains(cleanLine, "=") {
					parts := strings.SplitN(cleanLine, "=", 2)
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])

					if key == "net.ipv4.ip_forward" && val == "1" {
						*results = append(*results, LocalAuditResult{
							FilePath:    path,
							RuleID:      "CIS-4.1",
							Title:       "IP Forwarding Enabled",
							Description: "IP forwarding is enabled. Unless this system acts as a router, forwarding should be disabled to prevent routing malicious packets between subnets.",
							Severity:    "medium",
							Proof:       fmt.Sprintf("Line %d: net.ipv4.ip_forward = %s", lineNum, val),
						})
					}
					if key == "net.ipv4.conf.all.accept_redirects" && val == "1" {
						*results = append(*results, LocalAuditResult{
							FilePath:    path,
							RuleID:      "CIS-4.1",
							Title:       "ICMP Redirects Accepted",
							Description: "The system accepts ICMP redirect messages, which can make it vulnerable to Man-in-the-Middle (MitM) attacks or routing table alterations.",
							Severity:    "low",
							Proof:       fmt.Sprintf("Line %d: net.ipv4.conf.all.accept_redirects = %s", lineNum, val),
						})
					}
				}
			}
		}
	}
}
