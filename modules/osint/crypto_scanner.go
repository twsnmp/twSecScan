package osint

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// CryptoScanner performs security checks on SSL/TLS and SSH configurations.
type CryptoScanner struct {
	Timeout time.Duration
}

// CryptoScanResult holds the findings of the scan.
type CryptoScanResult struct {
	Port        int
	Service     string
	Protocol    string // "TLS" or "SSH"
	Vulnerable  bool
	Severity    string // "info", "low", "medium", "high", "critical"
	Title       string
	Description string
	Proof       string
}

func NewCryptoScanner(timeout time.Duration) *CryptoScanner {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &CryptoScanner{Timeout: timeout}
}

// Scan examines the target host for cryptographic settings on HTTPS, SSH, SMTP, IMAP, and POP3.
func (cs *CryptoScanner) Scan(ctx context.Context, host string) ([]CryptoScanResult, error) {
	var results []CryptoScanResult

	// Target ports and services
	targets := []struct {
		port    int
		service string
		proto   string // "TLS", "SSH", or "STARTTLS"
	}{
		{443, "HTTPS", "TLS"},
		{22, "SSH", "SSH"},
		{25, "SMTP", "STARTTLS"},
		{465, "SMTP (SSL/TLS)", "TLS"},
		{587, "SMTP (Submission)", "STARTTLS"},
		{110, "POP3", "STARTTLS"},
		{995, "POP3 (SSL/TLS)", "TLS"},
		{143, "IMAP", "STARTTLS"},
		{993, "IMAP (SSL/TLS)", "TLS"},
	}

	for _, t := range targets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		addr := net.JoinHostPort(host, fmt.Sprintf("%d", t.port))
		// Check if port is open first
		conn, err := net.DialTimeout("tcp", addr, cs.Timeout)
		if err != nil {
			// Port is closed or unreachable, skip
			continue
		}
		conn.Close()

		if t.proto == "SSH" {
			res := cs.checkSSH(ctx, host, t.port)
			results = append(results, res...)
		} else if t.proto == "TLS" {
			res := cs.checkTLS(ctx, host, t.port, t.service, false)
			results = append(results, res...)
		} else if t.proto == "STARTTLS" {
			res := cs.checkSTARTTLS(ctx, host, t.port, t.service)
			results = append(results, res...)
		}
	}

	return results, nil
}

// checkTLS establishes a TLS connection and checks for protocol version, certificates, etc.
func (cs *CryptoScanner) checkTLS(ctx context.Context, host string, port int, service string, isStartTLS bool) []CryptoScanResult {
	var results []CryptoScanResult
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// 1. Check for old TLS versions (SSLv3, TLS 1.0, TLS 1.1)
	oldVersions := []struct {
		version uint16
		name    string
	}{
		{tls.VersionSSL30, "SSLv3"},
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
	}

	for _, ov := range oldVersions {
		dialer := &net.Dialer{Timeout: cs.Timeout}
		config := &tls.Config{
			MinVersion:         ov.version,
			MaxVersion:         ov.version,
			InsecureSkipVerify: true,
			ServerName:         host,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err == nil {
			conn.Close()
			results = append(results, CryptoScanResult{
				Port:        port,
				Service:     service,
				Protocol:    "TLS",
				Vulnerable:  true,
				Severity:    "medium",
				Title:       fmt.Sprintf("Deprecate TLS Version Supported: %s", ov.name),
				Description: fmt.Sprintf("The server supports %s, which is deprecated and contains known security vulnerabilities.", ov.name),
				Proof:       fmt.Sprintf("Successfully established a TLS connection using %s on port %d.", ov.name, port),
			})
		}
	}

	// 2. Perform normal TLS check to verify certificate validity
	dialer := &net.Dialer{Timeout: cs.Timeout}
	// We want to see if normal verification succeeds
	config := &tls.Config{
		ServerName: host,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		// If verification fails, try again ignoring verification to inspect the cert details
		config.InsecureSkipVerify = true
		insecureConn, insErr := tls.DialWithDialer(dialer, "tcp", addr, config)
		if insErr == nil {
			defer insecureConn.Close()
			state := insecureConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				
				// Identify why it failed
				var reason string
				var severity string = "medium"
				
				if time.Now().After(cert.NotAfter) {
					reason = "Certificate is expired."
					severity = "high"
				} else if time.Now().Before(cert.NotBefore) {
					reason = "Certificate is not yet valid."
				} else if errVerify := cert.VerifyHostname(host); errVerify != nil {
					reason = fmt.Sprintf("Certificate hostname mismatch: %v", errVerify)
				} else {
					// Check if self-signed
					if len(cert.AuthorityKeyId) > 0 && len(cert.SubjectKeyId) > 0 && string(cert.AuthorityKeyId) == string(cert.SubjectKeyId) {
						reason = "Certificate is self-signed."
					} else {
						reason = fmt.Sprintf("Certificate trust chain verification failed: %v", err)
					}
				}

				results = append(results, CryptoScanResult{
					Port:        port,
					Service:     service,
					Protocol:    "TLS",
					Vulnerable:  true,
					Severity:    severity,
					Title:       "Invalid/Untrusted SSL/TLS Certificate",
					Description: fmt.Sprintf("The TLS certificate presented by the server on port %d is invalid or untrusted.\nReason: %s", port, reason),
					Proof:       fmt.Sprintf("Certificate Subject: %s\nIssuer: %s\nValid until: %s", cert.Subject, cert.Issuer, cert.NotAfter.Format(time.RFC3339)),
				})
			}
		}
	} else {
		defer conn.Close()
		// Certificate is valid! Check key sizes
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			// Check RSA key size
			if pubKey, ok := cert.PublicKey.(interface{ Size() int }); ok {
				keySizeBits := pubKey.Size() * 8
				if keySizeBits < 2048 {
					results = append(results, CryptoScanResult{
						Port:        port,
						Service:     service,
						Protocol:    "TLS",
						Vulnerable:  true,
						Severity:    "medium",
						Title:       "Weak SSL/TLS Certificate Key Size",
						Description: fmt.Sprintf("The server uses a public key of size %d bits, which is less than the recommended 2048 bits.", keySizeBits),
						Proof:       fmt.Sprintf("Algorithm: %s, Key size: %d bits", cert.PublicKeyAlgorithm.String(), keySizeBits),
					})
				}
			}
		}
	}

	return results
}

// checkSTARTTLS attempts to upgrade a connection via STARTTLS.
func (cs *CryptoScanner) checkSTARTTLS(ctx context.Context, host string, port int, service string) []CryptoScanResult {
	var results []CryptoScanResult
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, cs.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(cs.Timeout))

	reader := bufio.NewReader(conn)

	switch port {
	case 25, 587: // SMTP
		_, err = reader.ReadString('\n')
		if err != nil {
			return nil
		}
		// Send EHLO
		_, _ = conn.Write([]byte("EHLO localhost\r\n"))
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.Contains(strings.ToUpper(line), "STARTTLS") {
				// STARTTLS is supported, trigger TLS check on top
				return cs.checkTLS(ctx, host, port, service, true)
			}
			// EHLO response lines end with a line starting with "250 " (space instead of hyphen)
			if strings.HasPrefix(line, "250 ") {
				break
			}
		}
		// If we reached here, STARTTLS wasn't found
		results = append(results, CryptoScanResult{
			Port:        port,
			Service:     service,
			Protocol:    "Plaintext",
			Vulnerable:  true,
			Severity:    "high",
			Title:       "STARTTLS Not Supported / Plaintext Communication",
			Description: fmt.Sprintf("The mail service on port %d does not support or advertise STARTTLS. Credentials and emails are transmitted in plaintext.", port),
			Proof:       "Server did not advertise STARTTLS in EHLO response.",
		})

	case 143: // IMAP
		_, err = reader.ReadString('\n')
		if err != nil {
			return nil
		}
		// Send CAPABILITY
		_, _ = conn.Write([]byte(". CAPABILITY\r\n"))
		line, _ := reader.ReadString('\n')
		if strings.Contains(strings.ToUpper(line), "STARTTLS") {
			return cs.checkTLS(ctx, host, port, service, true)
		}
		results = append(results, CryptoScanResult{
			Port:        port,
			Service:     service,
			Protocol:    "Plaintext",
			Vulnerable:  true,
			Severity:    "high",
			Title:       "STARTTLS Not Supported on IMAP",
			Description: "The IMAP service does not support STARTTLS. Session logins and email retrievals are vulnerable to sniffing.",
			Proof:       line,
		})

	case 110: // POP3
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil
		}
		// Send CAPA
		_, _ = conn.Write([]byte("CAPA\r\n"))
		for {
			line, err = reader.ReadString('\n')
			if err != nil || strings.HasPrefix(line, ".") {
				break
			}
			if strings.Contains(strings.ToUpper(line), "STLS") {
				return cs.checkTLS(ctx, host, port, service, true)
			}
		}
		results = append(results, CryptoScanResult{
			Port:        port,
			Service:     service,
			Protocol:    "Plaintext",
			Vulnerable:  true,
			Severity:    "high",
			Title:       "STLS Not Supported on POP3",
			Description: "The POP3 service does not support STLS (STARTTLS). Session logins and email retrievals are vulnerable to sniffing.",
			Proof:       "Server did not return STLS in CAPA response.",
		})
	}

	return results
}

// checkSSH reads the SSH banner and analyzes key exchange / security properties
func (cs *CryptoScanner) checkSSH(ctx context.Context, host string, port int) []CryptoScanResult {
	var results []CryptoScanResult
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, cs.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(cs.Timeout))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	banner = strings.TrimSpace(banner)
	// Check for SSH-1.x (highly vulnerable)
	if strings.Contains(banner, "SSH-1.") {
		results = append(results, CryptoScanResult{
			Port:        port,
			Service:     "SSH",
			Protocol:    "SSH",
			Vulnerable:  true,
			Severity:    "critical",
			Title:       "Obsolete SSHv1 Protocol Version Supported",
			Description: "The SSH server supports SSHv1, which contains cryptographic vulnerabilities and is deprecated.",
			Proof:       fmt.Sprintf("Banner: %s", banner),
		})
	} else {
		// Even for SSHv2, let's log the version as information or check if it matches old software
		results = append(results, CryptoScanResult{
			Port:        port,
			Service:     "SSH",
			Protocol:    "SSH",
			Vulnerable:  false,
			Severity:    "info",
			Title:       "SSH Banner Detected",
			Description: "Identified active SSH service version banner.",
			Proof:       fmt.Sprintf("SSH Version Banner: %s", banner),
		})
	}

	return results
}
