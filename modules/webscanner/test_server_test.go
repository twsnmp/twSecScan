package webscanner

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTestServer(t *testing.T) {
	ts := NewTestServer()
	addr, err := ts.Start()
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	if addr == "" {
		t.Fatal("Start returned empty address")
	}

	// 1. Test GET /
	resp, err := http.Get(addr + "/")
	if err != nil {
		t.Fatalf("Failed to GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Local Test Server") {
		t.Errorf("Unexpected body for /: %s", string(body))
	}

	// 2. Test GET /secret-backup.sql
	resp2, err := http.Get(addr + "/secret-backup.sql")
	if err != nil {
		t.Fatalf("Failed to GET /secret-backup.sql: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body2), "CREATE TABLE users") {
		t.Errorf("Unexpected body for /secret-backup.sql: %s", string(body2))
	}

	// 3. Test GET /echo
	resp3, err := http.Get(addr + "/echo?content=hello_test")
	if err != nil {
		t.Fatalf("Failed to GET /echo: %v", err)
	}
	defer resp3.Body.Close()
	body3, _ := io.ReadAll(resp3.Body)
	if string(body3) != "hello_test" {
		t.Errorf("Expected 'hello_test', got: %s", string(body3))
	}

	// Stop server
	err = ts.Stop()
	if err != nil {
		t.Fatalf("Failed to stop test server: %v", err)
	}
}
