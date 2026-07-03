package webscanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
  <p>For support, please contact us at support@example.com or 03-1234-5678 (Zip: 100-0001).</p>
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

	// OpenAPI Specification Mock Endpoint
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
  "openapi": "3.0.0",
  "info": {
    "title": "Mock Vulnerable API",
    "version": "1.0.0"
  },
  "paths": {
    "/api/v1/users": {
      "get": {
        "summary": "Get users",
        "parameters": [
          {
            "name": "id",
            "in": "query",
            "required": true,
            "schema": {
              "type": "integer"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      },
      "post": {
        "summary": "Create user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "username": {
                    "type": "string"
                  },
                  "email": {
                    "type": "string"
                  }
                },
                "required": ["username"]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Created"
          }
        }
      }
    }
  }
}`)
	})

	// API Endpoint GET /api/v1/users
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			idStr := r.URL.Query().Get("id")
			// Insecure reflection or SQL injection emulation
			if strings.Contains(idStr, "'") || strings.Contains(idStr, "UNION") {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error: syntax error near '"+idStr+"'")
				return
			}
			if strings.Contains(idStr, "<script>") {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, "User ID: "+idStr)
				return
			}
			// Boundary value test (non-integer check)
			if idStr == "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, "Bad Request: id is required")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id": %s, "name": "Test User"}`, idStr)
		} else if r.Method == http.MethodPost {
			// POST JSON Endpoint
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			bodyStr := string(body)
			// Emulate SQLi or XSS in body parameters
			if strings.Contains(bodyStr, "'") || strings.Contains(bodyStr, "UNION") {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error: SQL syntax error in JSON input: "+bodyStr)
				return
			}
			if strings.Contains(bodyStr, "<script>") {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, "Reflected payload: "+bodyStr)
				return
			}
			// Length boundary check
			if len(bodyStr) > 500 {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Buffer overflow or unexpected error due to payload size")
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"status": "created"}`)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
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
