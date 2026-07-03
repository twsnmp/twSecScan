package webscanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// LinkResult represents the check result for a single URL.
type LinkResult struct {
	URL        string        `json:"url"`
	Source     string        `json:"source"`
	StatusCode int           `json:"statusCode"`
	Error      string        `json:"error"`
	Duration   time.Duration `json:"duration"`
	Broken     bool          `json:"broken"`
	Internal   bool          `json:"internal"`
	HeaderFindings []HeaderFinding `json:"headerFindings,omitempty"`
}

// Options configures the crawler's execution.
type Options struct {
	Concurrency int           `json:"concurrency"`
	Timeout     time.Duration `json:"timeout"`
	UserAgent   string        `json:"userAgent"`
}

// Crawler scans websites recursively checking for broken links.
type Crawler struct {
	baseURL    *url.URL
	visited    map[string]bool
	visitedMu  sync.Mutex
	httpClient *http.Client
}

type crawlJob struct {
	url    string
	source string
}

// NewCrawler creates a new Crawler instance.
func NewCrawler() *Crawler {
	return &Crawler{}
}

// Start starts crawling from the startURL and checks for broken links.
// It returns a read-only channel where results are sent as they are discovered.
func (c *Crawler) Start(ctx context.Context, startURLStr string, opts Options) (<-chan LinkResult, error) {
	parsedStartURL, err := url.Parse(startURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid start URL: %w", err)
	}

	c.baseURL = parsedStartURL
	c.visited = make(map[string]bool)

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	c.httpClient = &http.Client{
		Timeout: timeout,
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	resultsChan := make(chan LinkResult, 100)
	jobsChan := make(chan crawlJob, concurrency*2)

	var wg sync.WaitGroup

	enqueue := func(jobURL, source string) {
		c.visitedMu.Lock()
		defer c.visitedMu.Unlock()

		normURL := normalizeURL(jobURL)
		if c.visited[normURL] {
			return
		}
		c.visited[normURL] = true

		wg.Add(1)
		go func() {
			select {
			case jobsChan <- crawlJob{url: normURL, source: source}:
			case <-ctx.Done():
				wg.Done()
			}
		}()
	}

	// Start workers
	for i := 0; i < concurrency; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobsChan:
					if !ok {
						return
					}
					c.processJob(ctx, job, enqueue, resultsChan, opts.UserAgent)
					wg.Done()
				}
			}
		}()
	}

	// Enqueue the first job
	enqueue(startURLStr, "")

	// Monitor completion and close channels
	go func() {
		wg.Wait()
		close(jobsChan)
		close(resultsChan)
	}()

	return resultsChan, nil
}

func (c *Crawler) processJob(ctx context.Context, job crawlJob, enqueue func(string, string), resultsChan chan<- LinkResult, userAgent string) {
	u, err := url.Parse(job.url)
	if err != nil {
		resultsChan <- LinkResult{
			URL:    job.url,
			Source: job.source,
			Error:  err.Error(),
			Broken: true,
		}
		return
	}

	isInternal := u.Host == c.baseURL.Host

	req, err := http.NewRequestWithContext(ctx, "GET", job.url, nil)
	if err != nil {
		resultsChan <- LinkResult{
			URL:      job.url,
			Source:   job.source,
			Error:    err.Error(),
			Broken:   true,
			Internal: isInternal,
		}
		return
	}

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		resultsChan <- LinkResult{
			URL:      job.url,
			Source:   job.source,
			Error:    err.Error(),
			Duration: duration,
			Broken:   true,
			Internal: isInternal,
		}
		return
	}
	defer resp.Body.Close()

	broken := resp.StatusCode >= 400

	// Check HTTP headers for security issues or leaks
	headerFindings := CheckHeaders(job.url, resp.Header)

	resultsChan <- LinkResult{
		URL:            job.url,
		Source:         job.source,
		StatusCode:     resp.StatusCode,
		Duration:       duration,
		Broken:         broken,
		Internal:       isInternal,
		HeaderFindings: headerFindings,
	}

	// Only parse HTML and follow links if it's internal, not broken, and contains HTML.
	if isInternal && !broken {
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(strings.ToLower(contentType), "text/html") {
			links := c.extractLinks(resp.Body, u)
			for _, link := range links {
				enqueue(link, job.url)
			}
		}
	}
}

func (c *Crawler) extractLinks(r io.Reader, base *url.URL) []string {
	var links []string
	z := html.NewTokenizer(r)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return links
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.Data == "a" {
				for _, a := range t.Attr {
					if a.Key == "href" {
						resolved := resolveURL(a.Val, base)
						if resolved != "" {
							links = append(links, resolved)
						}
					}
				}
			}
		}
	}
}

func normalizeURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}

func resolveURL(ref string, base *url.URL) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(u)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	return resolved.String()
}
