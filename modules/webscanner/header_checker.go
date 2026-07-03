package webscanner

import (
	"fmt"
	"net/http"
	"strings"
)

// HeaderFinding represents a security issue found in HTTP headers.
type HeaderFinding struct {
	Header      string `json:"header"`
	Status      string `json:"status"`      // e.g., "Missing", "Insecure", "Information Leak"
	Severity    string `json:"severity"`    // "high", "medium", "low", "info"
	Description string `json:"description"`
	Proof       string `json:"proof"`
}

// CheckHeaders inspects HTTP response headers for security issues.
func CheckHeaders(targetURL string, headers http.Header) []HeaderFinding {
	var findings []HeaderFinding

	isHTTPS := strings.HasPrefix(strings.ToLower(targetURL), "https://")

	// 1. Strict-Transport-Security (HSTS) - Only applicable for HTTPS
	if isHTTPS {
		hsts := headers.Get("Strict-Transport-Security")
		if hsts == "" {
			findings = append(findings, HeaderFinding{
				Header:      "Strict-Transport-Security",
				Status:      "Missing",
				Severity:    "low",
				Description: "HTTP Strict Transport Security (HSTS) header is missing. This header forces browsers to use secure HTTPS connections instead of HTTP.",
				Proof:       "Strict-Transport-Security header not found in response.",
			})
		}
	}

	// 2. Content-Security-Policy (CSP)
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		findings = append(findings, HeaderFinding{
			Header:      "Content-Security-Policy",
			Status:      "Missing",
			Severity:    "low",
			Description: "Content Security Policy (CSP) header is missing. CSP helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
			Proof:       "Content-Security-Policy header not found in response.",
		})
	}

	// 3. X-Frame-Options
	xfo := headers.Get("X-Frame-Options")
	if xfo == "" {
		findings = append(findings, HeaderFinding{
			Header:      "X-Frame-Options",
			Status:      "Missing",
			Severity:    "medium",
			Description: "X-Frame-Options header is missing. This header protects users against clickjacking attacks by controlling whether the page can be rendered in a <frame>, <iframe>, <embed> or <object>.",
			Proof:       "X-Frame-Options header not found in response.",
		})
	}

	// 4. X-Content-Type-Options
	xcto := headers.Get("X-Content-Type-Options")
	if xcto == "" {
		findings = append(findings, HeaderFinding{
			Header:      "X-Content-Type-Options",
			Status:      "Missing",
			Severity:    "low",
			Description: "X-Content-Type-Options header is missing. This header prevents browsers from MIME-sniffing a response away from the declared content-type.",
			Proof:       "X-Content-Type-Options header not found in response.",
		})
	} else if strings.ToLower(strings.TrimSpace(xcto)) != "nosniff" {
		findings = append(findings, HeaderFinding{
			Header:      "X-Content-Type-Options",
			Status:      "Insecure",
			Severity:    "low",
			Description: "X-Content-Type-Options header is not set to 'nosniff'. This may allow browsers to mime-sniff the response.",
			Proof:       fmt.Sprintf("X-Content-Type-Options: %s", xcto),
		})
	}

	// 5. Referrer-Policy
	rp := headers.Get("Referrer-Policy")
	if rp == "" {
		findings = append(findings, HeaderFinding{
			Header:      "Referrer-Policy",
			Status:      "Missing",
			Severity:    "low",
			Description: "Referrer-Policy header is missing. This header governs which referrer information, sent in the Referer header, should be included with requests made.",
			Proof:       "Referrer-Policy header not found in response.",
		})
	}

	// 6. Permissions-Policy
	pp := headers.Get("Permissions-Policy")
	if pp == "" {
		findings = append(findings, HeaderFinding{
			Header:      "Permissions-Policy",
			Status:      "Missing",
			Severity:    "low",
			Description: "Permissions-Policy header is missing. This header allows a site to control which browser features (like camera, microphone, geolocation) can be used.",
			Proof:       "Permissions-Policy header not found in response.",
		})
	}

	// 7. Server (Information Leak)
	if server := headers.Get("Server"); server != "" {
		findings = append(findings, HeaderFinding{
			Header:      "Server",
			Status:      "Information Leak",
			Severity:    "low",
			Description: "Server header leaks web server software information. Exposing specific version info can help attackers find known vulnerabilities.",
			Proof:       fmt.Sprintf("Server: %s", server),
		})
	}

	// 8. X-Powered-By (Information Leak)
	if xpb := headers.Get("X-Powered-By"); xpb != "" {
		findings = append(findings, HeaderFinding{
			Header:      "X-Powered-By",
			Status:      "Information Leak",
			Severity:    "low",
			Description: "X-Powered-By header leaks application framework or language details. This exposes technologies used behind the website.",
			Proof:       fmt.Sprintf("X-Powered-By: %s", xpb),
		})
	}

	// 9. X-AspNet-Version (Information Leak)
	if xanv := headers.Get("X-AspNet-Version"); xanv != "" {
		findings = append(findings, HeaderFinding{
			Header:      "X-AspNet-Version",
			Status:      "Information Leak",
			Severity:    "low",
			Description: "X-AspNet-Version header leaks Microsoft ASP.NET version details.",
			Proof:       fmt.Sprintf("X-AspNet-Version: %s", xanv),
		})
	}

	return findings
}
