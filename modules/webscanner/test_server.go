package webscanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type TestServer struct {
	server   *http.Server
	listener net.Listener
	mu       sync.Mutex
	addr     string
}

func NewTestServer() *TestServer {
	return &TestServer{}
}

func (ts *TestServer) Start() (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.server != nil {
		return ts.addr, nil
	}

	var listener net.Listener
	var err error
	var chosenPort int

	for port := 8081; port <= 8089; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			chosenPort = port
			break
		}
	}

	if listener == nil {
		return "", fmt.Errorf("failed to bind to any port in range 8081-8089")
	}

	mux := http.NewServeMux()
	
	// Top page containing links to other pages (for Crawler / Link Checker and Validation Tester discovery)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Only handle exactly "/"
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html>
<head><title>Local Test Server</title></head>
<body>
  <h1>Local Test Server</h1>
  <p>This server emulates various security misconfigurations for development and testing.</p>
  <ul>
    <li><a href="/echo?content=InitialContent">Input Validation Tester (/echo)</a></li>
    <li><a href="/secret-backup.sql">Exposed SQL Backup File (/secret-backup.sql)</a></li>
    <li><a href="/broken-link">Broken Link Target (/broken-link)</a></li>
  </ul>
</body>
</html>`)
	})

	// Validation Tester Endpoint
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		content := r.URL.Query().Get("content")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, content)
	})

	// Broken link target
	mux.HandleFunc("/broken-link", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Exposed files for Directory Checker / Asset Auditor (matching directories.txt paths)
	mux.HandleFunc("/secret-backup.sql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "-- Dummy SQL Backup\nCREATE TABLE users (id INT, username VARCHAR(50));\n")
	})

	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "APP_ENV=production\nDATABASE_URL=postgres://admin:super-secret-password@localhost:5432/db\nAPI_KEY=dummy_key_123456789\n")
	})

	mux.HandleFunc("/backup.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		fmt.Fprint(w, "PK\x03\x04dummy-zip-content")
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><body><h1>Admin Console</h1><p>Restrict access to this console.</p></body></html>")
	})

	ts.server = &http.Server{
		Handler: mux,
	}
	ts.listener = listener
	ts.addr = fmt.Sprintf("http://localhost:%d", chosenPort)

	go func() {
		if err := ts.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			// Server closed
		}
	}()

	return ts.addr, nil
}

func (ts *TestServer) Stop() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := ts.server.Shutdown(ctx)
	ts.server = nil
	ts.listener = nil
	ts.addr = ""

	return err
}
