package osint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCryptoScanner_ScanTLS(t *testing.T) {
	// Start a mock TLS server
	cert, err := tls.X509KeyPair(testCertPEM, testKeyPEM)
	if err != nil {
		t.Fatalf("Failed to load test key pair: %v", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn, ok := c.(*tls.Conn)
				if ok {
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to parse port: %v", err)
	}

	scanner := NewCryptoScanner(1 * time.Second)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	results := scanner.checkTLS(context.Background(), "127.0.0.1", port, "TestTLS", false)
	if len(results) == 0 {
		t.Log("No vulnerabilities found")
	} else {
		for _, res := range results {
			t.Logf("Found checkTLS result: %s - Severity: %s", res.Title, res.Severity)
		}
	}
}

// Generated via openssl
var testCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIUHDGHxzqToEmMYNexLxqDOSJtLYcwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTbW9jay10bHMtc2VydmVyLnRzdDAeFw0yNjA3MDMxMTU0
MTBaFw0yNzA3MDMxMTU0MTBaMB4xHDAaBgNVBAMME21vY2stdGxzLXNlcnZlci50
c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClzPb0T950p4Ok8H6U
y38mgeIXsfVKzRre0MAJ1MwwN6sZ0kaPN3hYWoX5Qh8bLON9ES2sh8IXuKHgQOtp
NA+5jZJV7rTeV6IBk1Ni2YNolOP3vOETjXpDWusKNLE54z4xJSHbbqeV0yoCGsVn
+nWVq2fcNMmhtQzkSVHrvoll01XZ0fceWKd2fjeRE7rhcuaDTLHZ+OWrLCZeyNPT
ebrHOUarPcl8UJRuV/auc1078VL4mSeJoRQnkYL2Nw2O8qX2NJMg9yQ08F0fuqYk
f7EV5E8r93FjW9N9LjTCpXzoRhgfrFT6nn2R2tIW5Txn04ShImkgyP5fSkXsCQFU
nrxJAgMBAAGjUzBRMB0GA1UdDgQWBBSd60qT/msidPCEulMpiEdXTX1NHzAfBgNV
HSMEGDAWgBSd60qT/msidPCEulMpiEdXTX1NHzAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQAoKIUvzYX8CK07w544sQcgaphAiQp+FhFNlYwhR7/g
epxmBFoYGFkfiKF9A6JbYpzwcXmt5OWaPCUeAdI+fbdAR2KGkHEYIxC/DIAk8Eoo
oOrJpYMjDMT3JdbA1wwSwI7i+VFVwCuTu8QI1HaEkOml6Hqf/kGit4ZOGmoGBX6y
ja4qg9EEYzlMZlaGJ+Q+VNe94cHqaivj9Gk9RGrA578lcVnpXe46uYnknwjAoZUj
UgLkLj5c0+2IK3vSWH89du8aAgRcvmwAnvQugpvctNoaGW4sqPv4B9M3gYgR8gmO
C5jVxWkMAz1vtjifgN2duFiR1m1dYvW4j7352OyjgNKz
-----END CERTIFICATE-----`)

var testKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClzPb0T950p4Ok
8H6Uy38mgeIXsfVKzRre0MAJ1MwwN6sZ0kaPN3hYWoX5Qh8bLON9ES2sh8IXuKHg
QOtpNA+5jZJV7rTeV6IBk1Ni2YNolOP3vOETjXpDWusKNLE54z4xJSHbbqeV0yoC
GsVn+nWVq2fcNMmhtQzkSVHrvoll01XZ0fceWKd2fjeRE7rhcuaDTLHZ+OWrLCZe
yNPTebrHOUarPcl8UJRuV/auc1078VL4mSeJoRQnkYL2Nw2O8qX2NJMg9yQ08F0f
uqYkf7EV5E8r93FjW9N9LjTCpXzoRhgfrFT6nn2R2tIW5Txn04ShImkgyP5fSkXs
CQFUnrxJAgMBAAECggEADhcUl5+f/pbr050SjM+cbyfTkILxnxk+IthnsY4xihl5
A3lAwNQMeKm8v/mUDimq7YqDsKla38wziYzK1MZ1XaX/3Sirm0ekP3EHQZvNlJou
o3OcRx6bWNUFq3jd5NcAhomqzmyhdlSbOdGPnC4HRyBpc6fSyNjLjy0B9sBbCdmg
YUYwgbTHTZsvLJny6fjzsWrCpCDw+dvqwN2goM7lM0ca6wqj9a12jY+8IfnahBVg
69fS+TxojmYr4QOLPkJS20mpmMsEHywd220yC4g9cXQamAyQkJxqchkrjWdfbOqU
vE+yFGv2KnSfpeJytonYdloUYCn0MnyRu5fLyKhZnwKBgQDXdiuwhxxzLtVfGD/t
uznT5GLLYnJW2j4fCNdV+GUC0qkIkRK/7QeVaSGndCvD4t/LK/EaqikvBkuwA3U0
0RgQ6thsRCgdYmfn47a+iOBQTdaRVHvUDbsKw9vdI4ilPp1+hEYejhcCBRi74gr0
R8d7FAZHbHzcR73WmXHQZUbZLwKBgQDE/tiMUusrC9wyu78GT1gu5SB1JW3S98Zb
I6P4+ZmxoJJwnFBz1ppR6pu+lxsbCj517pcNQsfEpE60lIKiKuzBgpF/wpqJ+UsS
IflPqU6SyDZfQzGVVByzvYuJz78mwStRAsbhl0BfDjoqIboaHX5ISKqoUtBy4KeR
H0UO2rL0BwKBgBDXsPScqzGp0I4ddCneP9f7e2mQqYV2i/KbG1IiF6tP0lzUElYk
bjpUvIe9ggpO+tWD+tXtxUhiwpngu1HEoo/3+7EC5uvdHGg5GbjtNDOy0foMU52w
8RUXWGGB/JWGPoN8TYrn6o6C3XsaYWbVEZfiadc9eMkzZniXCBmVQSOLAoGBALsN
VWeg0GZWY6bUuOTv8EbPD8vMV4Tr+q/NnsQplTOhyYseEhJ8IppHz8zgRD+fsYFf
pJRV5cQlVAqJvaToZ1izdx6+FOmQCiVUlxt6Iv6jF2XLMsidToepIlcgKVxOLahF
n7zTVq8rnjUlQ0XK3X8baNhdkkqSYOoeq/8X0LZ/AoGAfBJH8M7qZriQV1bP+uKa
QeBB8nNmjRYfHx87Nwgej77Q+mYtQdbSlXaFCJKu9yWl35RwXQrT+CBYgff0OLAQ
kCc8fu6BmRAkOW3LmixayC2MOQK1wLGuVKnPP74Kx4ZKEhj/GxhbuXN7DofLxRJy
3KUW0vMjTkRgi/gjkv5fxSk=
-----END PRIVATE KEY-----`)
