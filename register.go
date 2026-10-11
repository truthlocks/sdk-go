package truthlock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const sandboxRegisterURL = "https://sandbox-api.truthlocks.com/v1/developers/register"

// Sentinel errors for registration.
var (
	ErrAlreadyRegistered = errors.New("developer already registered with this email")
	ErrRateLimited       = errors.New("registration rate limit exceeded")
)

// RegisterResult contains the response from a successful developer registration.
type RegisterResult struct {
	// APIKey is the generated API key for the new developer account.
	APIKey string `json:"api_key"`
	// TenantID is the assigned tenant identifier.
	TenantID string `json:"tenant_id"`
	// Plan is the initial plan tier (e.g. "sandbox", "starter").
	Plan string `json:"plan"`
	// Limits contains rate and usage limits for the assigned plan.
	Limits RegisterLimits `json:"limits"`
	// UpgradeURL is the URL to upgrade to a paid plan.
	UpgradeURL string `json:"upgrade_url"`
	// SandboxBaseURL is the base URL for sandbox API calls.
	SandboxBaseURL string `json:"sandbox_base_url"`
}

// RegisterLimits describes the rate and usage constraints for the developer tier.
type RegisterLimits struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	RequestsPerDay    int `json:"requests_per_day"`
	AttestationsMax   int `json:"attestations_max"`
}

// RegisterOption configures optional parameters for Register.
type RegisterOption func(*registerOptions)

type registerOptions struct {
	source     string
	httpClient *http.Client
}

// WithSource sets the registration source (e.g. "cli", "docs", "website").
func WithSource(source string) RegisterOption {
	return func(o *registerOptions) {
		o.source = source
	}
}

// Register creates a new developer account on the Truthlocks sandbox.
// It returns the API key, tenant ID, and plan limits on success.
func Register(ctx context.Context, email string, opts ...RegisterOption) (*RegisterResult, error) {
	if strings.TrimSpace(email) == "" {
		return nil, fmt.Errorf("truthlock: email is required for registration")
	}

	options := &registerOptions{
		httpClient: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	for _, opt := range opts {
		opt(options)
	}

	body := map[string]string{
		"email": email,
	}
	if options.source != "" {
		body["source"] = options.source
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("truthlock: failed to marshal register request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sandboxRegisterURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("truthlock: failed to create register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := options.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("truthlock: register request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil {
		return nil, fmt.Errorf("truthlock: failed to read register response: %w", err)
	}

	if len(respBody) > 1024*1024 {
		return nil, fmt.Errorf("truthlock: registration response exceeds 1 MiB")
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var result RegisterResult
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, fmt.Errorf("truthlock: failed to decode register response: %w", err)
		}
		if result.APIKey == "" || result.TenantID == "" {
			return nil, fmt.Errorf("truthlock: registration response is missing credentials")
		}
		return &result, nil

	case http.StatusConflict:
		return nil, ErrAlreadyRegistered

	case http.StatusTooManyRequests:
		return nil, ErrRateLimited

	default:
		var apiErr TruthlockError
		if err := json.Unmarshal(respBody, &apiErr); err != nil {
			return nil, fmt.Errorf("truthlock: registration failed with status %d: %s", resp.StatusCode, string(respBody))
		}
		apiErr.Status = resp.StatusCode
		if apiErr.Message == "" {
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
		return nil, &apiErr
	}
}
