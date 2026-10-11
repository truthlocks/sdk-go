// Package truthlock provides an authenticated HTTP client for Truthlocks.
package truthlock

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds the configuration for the Truthlock client.
type Config struct {
	// BaseURL is the base URL of the Truthlock API gateway.
	BaseURL string
	// TenantID is deprecated. The server derives the workspace from credentials.
	TenantID string
	// APIKey is an optional API key for service-to-service authentication.
	APIKey string
	// BearerToken authenticates user operations that require a user identity.
	BearerToken string
	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client
	// Debug enables debug logging.
	Debug bool
}

// Client is the main Truthlock API client.
type Client struct {
	config Config
	http   *http.Client

	// Issuers provides issuer management operations.
	Issuers *IssuersService
	// Keys provides key management operations.
	Keys *KeysService
	// Attestations provides attestation operations.
	Attestations *AttestationsService
	// Verify provides verification operations.
	Verify *VerifyService
	// Audit provides audit log operations.
	Audit *AuditService
	// Receipts provides receipt lifecycle operations (Ticket 81).
	Receipts *ReceiptsService
}

// NewClient creates a new Truthlock client with the given configuration.
func NewClient(config Config) *Client {
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if config.BaseURL == "" {
		config.BaseURL = "https://api.truthlocks.com"
		if strings.HasPrefix(config.APIKey, "tl_test_") {
			config.BaseURL = "https://sandbox-api.truthlocks.com"
		}
	}
	httpClient := *config.HTTPClient
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 30 * time.Second
	}
	// Never forward credentials on redirects, including redirects to another host.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	c := &Client{
		config: config,
		http:   &httpClient,
	}

	c.Issuers = &IssuersService{client: c}
	c.Keys = &KeysService{client: c}
	c.Attestations = &AttestationsService{client: c}
	c.Verify = &VerifyService{client: c}
	c.Audit = &AuditService{client: c}
	c.Receipts = &ReceiptsService{client: c}

	return c
}

// request performs an authenticated HTTP request to the Truthlock API.
func (c *Client) request(ctx context.Context, method, path string, body, result interface{}) error {
	if c.config.APIKey == "" && c.config.BearerToken == "" {
		return fmt.Errorf("truthlocks: provide APIKey or BearerToken; TenantID alone cannot authenticate")
	}
	base, err := url.Parse(c.config.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil {
		return fmt.Errorf("truthlocks: invalid API base URL")
	}
	rel, err := url.Parse(path)
	if err != nil || rel.IsAbs() || rel.Host != "" || !strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return fmt.Errorf("truthlocks: request path must be an API-relative path")
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("truthlocks: encode request: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, base.ResolveReference(rel).String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.config.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.BearerToken)
	} else {
		req.Header.Set("X-API-Key", c.config.APIKey)
	}
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete {
		key, _ := ctx.Value(idempotencyContextKey{}).(string)
		if key == "" {
			var random [16]byte
			if _, err := rand.Read(random[:]); err != nil {
				return fmt.Errorf("truthlocks: generate idempotency key: %w", err)
			}
			key = hex.EncodeToString(random[:])
		}
		req.Header.Set("Idempotency-Key", key)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("truthlocks: HTTP request: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 32<<20+1))
	if err != nil {
		return fmt.Errorf("truthlocks: read response: %w", err)
	}
	if len(data) > 32<<20 {
		return fmt.Errorf("truthlocks: response exceeds 32 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		apiErr := &TruthlockError{Code: ErrorCode("HTTP_ERROR"), Status: response.StatusCode, Message: http.StatusText(response.StatusCode), TraceID: response.Header.Get("X-Request-ID")}
		var problem struct {
			Code    string                 `json:"code"`
			Message string                 `json:"message"`
			Detail  string                 `json:"detail"`
			Title   string                 `json:"title"`
			TraceID string                 `json:"trace_id"`
			Details map[string]interface{} `json:"details"`
		}
		if json.Unmarshal(data, &problem) == nil {
			if problem.Code != "" {
				apiErr.Code = ErrorCode(problem.Code)
			}
			for _, message := range []string{problem.Message, problem.Detail, problem.Title} {
				if message != "" {
					apiErr.Message = message
					break
				}
			}
			if problem.TraceID != "" {
				apiErr.TraceID = problem.TraceID
			}
			apiErr.Details = problem.Details
		}
		return apiErr
	}
	if result == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("truthlocks: invalid JSON response: %w", err)
	}
	return nil
}

type idempotencyContextKey struct{}

// WithIdempotencyKey lets an application retain a key across retries of one write.
// Reuse it only with the same operation and request body. The client does not retry writes automatically.
func WithIdempotencyKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, idempotencyContextKey{}, key)
}
