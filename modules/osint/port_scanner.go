package osint

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ScanPorts scans the specified ports on a target host concurrently.
// It respects context cancellation.
func ScanPorts(ctx context.Context, target string, ports []int, timeout time.Duration, concurrency int) ([]int, error) {
	if concurrency <= 0 {
		concurrency = 1
	}

	portsChan := make(chan int, len(ports))
	for _, p := range ports {
		portsChan <- p
	}
	close(portsChan)

	var wg sync.WaitGroup
	openPortsChan := make(chan int, len(ports))

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case port, ok := <-portsChan:
					if !ok {
						return
					}

					address := fmt.Sprintf("%s:%d", target, port)
					// Use Dialer to support context-based cancellation at the TCP connection level
					var dialer net.Dialer
					dialer.Timeout = timeout

					conn, err := dialer.DialContext(ctx, "tcp", address)
					if err == nil {
						conn.Close()
						openPortsChan <- port
					}
				}
			}
		}()
	}

	// Wait for workers to complete in a separate Goroutine so we can still handle context cancellation
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
	}

	close(openPortsChan)

	var openPorts []int
	for p := range openPortsChan {
		openPorts = append(openPorts, p)
	}

	sort.Ints(openPorts)
	return openPorts, nil
}
