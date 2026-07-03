package osint

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"twSecScan/embed"
)

func TestPortScanner(t *testing.T) {
	// Start a mock TCP listener on an ephemeral port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer l.Close()

	_, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}

	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	// We'll scan a slice of ports, including the open one and a likely closed one
	closedPort := 55432
	portsToScan := []int{closedPort, port}

	ctx := context.Background()
	openPorts, err := ScanPorts(ctx, "127.0.0.1", portsToScan, 200*time.Millisecond, 2)
	if err != nil {
		t.Fatalf("ScanPorts returned error: %v", err)
	}

	if len(openPorts) != 1 {
		t.Fatalf("expected exactly 1 open port, got %v", openPorts)
	}
	if openPorts[0] != port {
		t.Errorf("expected open port to be %d, got %d", port, openPorts[0])
	}
}

func TestPortScannerCancellation(t *testing.T) {
	// Test that scanner respects context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ports := []int{80, 443, 8080}
	_, err := ScanPorts(ctx, "127.0.0.1", ports, 500*time.Millisecond, 2)
	if err == nil {
		t.Error("expected error due to cancelled context, but got nil")
	}
}

func TestWordlistsEmbed(t *testing.T) {
	// Simply verify we can load the wordlists we created
	subs, err := embed.GetSubdomainWordlist()
	if err != nil {
		t.Fatalf("failed to get subdomain wordlist: %v", err)
	}
	if len(subs) == 0 {
		t.Error("subdomain wordlist is empty")
	}

	dirs, err := embed.GetDirectoryWordlist()
	if err != nil {
		t.Fatalf("failed to get directory wordlist: %v", err)
	}
	if len(dirs) == 0 {
		t.Error("directory wordlist is empty")
	}
}
