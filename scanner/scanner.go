package scanner

import (
	"io"
	"net/http"
	"time"
)

// Result — bir HTTP isteğinin sonucunu tutar
type Result struct {
	URL          string
	Method       string
	StatusCode   int
	ResponseTime time.Duration
	ResponseSize int64
	Headers      map[string][]string
	Body         string
	Error        string
}

// Client — HTTP isteklerini yöneten yapı
type Client struct {
	http    *http.Client
	headers map[string]string
}

// New — yeni bir Client oluşturur
func New(timeoutSec int, globalHeaders map[string]string) *Client {
	return &Client{
		http: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
			// Redirect'leri takip etme — güvenlik testlerinde önemli
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		headers: globalHeaders,
	}
}

// Do — verilen method, url ve header'larla istek atar
func (c *Client) Do(method, url string, extraHeaders map[string]string, body io.Reader) Result {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return Result{URL: url, Method: method, Error: err.Error()}
	}

	// Global header'ları ekle
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	// Endpoint'e özel header'ları ekle (override eder)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		return Result{URL: url, Method: method, ResponseTime: elapsed, Error: err.Error()}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	return Result{
		URL:          url,
		Method:       method,
		StatusCode:   resp.StatusCode,
		ResponseTime: elapsed,
		ResponseSize: int64(len(respBody)),
		Headers:      map[string][]string(resp.Header),
		Body:         string(respBody),
	}
}
