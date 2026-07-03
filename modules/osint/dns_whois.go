package osint

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// DNSRecords holds resolved records for a domain.
type DNSRecords struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	MX    []string `json:"mx"`
	TXT   []string `json:"txt"`
	NS    []string `json:"ns"`
	CNAME string   `json:"cname"`
}

// LookupDNS queries all common DNS records for the given domain using a custom or default resolver.
func LookupDNS(ctx context.Context, domain string) (*DNSRecords, error) {
	resolver := &net.Resolver{}

	records := &DNSRecords{}

	// IP (A and AAAA)
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err == nil {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				records.A = append(records.A, ip.IP.String())
			} else {
				records.AAAA = append(records.AAAA, ip.IP.String())
			}
		}
	}

	// MX
	mxs, err := resolver.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxs {
			records.MX = append(records.MX, fmt.Sprintf("%s (preference: %d)", mx.Host, mx.Pref))
		}
	}

	// TXT
	txts, err := resolver.LookupTXT(ctx, domain)
	if err == nil {
		records.TXT = txts
	}

	// NS
	nss, err := resolver.LookupNS(ctx, domain)
	if err == nil {
		for _, ns := range nss {
			records.NS = append(records.NS, ns.Host)
		}
	}

	// CNAME
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err == nil && cname != "" && !strings.EqualFold(cname, domain+".") && !strings.EqualFold(cname, domain) {
		records.CNAME = cname
	}

	return records, nil
}

// QueryWHOIS queries WHOIS data for a domain. It automatically queries the root server (whois.iana.org)
// to discover the referral WHOIS server and queries it for detailed records.
func QueryWHOIS(ctx context.Context, domain string) (string, error) {
	// First query the IANA WHOIS server
	ianaServer := "whois.iana.org:43"
	rawIANA, err := querySingleWHOIS(ctx, ianaServer, domain)
	if err != nil {
		// Fallback to query standard WHOIS ports directly if IANA fails, e.g. using whois.verisign-grs.com for .com
		// But let's try to extract referral first
		return "", fmt.Errorf("failed to query IANA WHOIS: %w", err)
	}

	referralServer := parseReferralServer(rawIANA)
	if referralServer == "" {
		// If no referral server found in IANA response, return IANA response as fallback
		return rawIANA, nil
	}

	// Query the referral server
	rawReferral, err := querySingleWHOIS(ctx, referralServer+":43", domain)
	if err != nil {
		// If referral server fails, return IANA response
		return rawIANA, nil
	}

	return rawReferral, nil
}

func querySingleWHOIS(ctx context.Context, server, query string) (string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send domain query with CRLF
	_, err = conn.Write([]byte(query + "\r\n"))
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			n, err := conn.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				if err == io.EOF {
					return sb.String(), nil
				}
				return "", err
			}
		}
	}
}

func parseReferralServer(ianaResponse string) string {
	lines := strings.Split(ianaResponse, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Standard IANA format: "refer: whois.verisign-grs.com" or "whois: whois.verisign-grs.com"
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(strings.ToLower(line), "whois:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
