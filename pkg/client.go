package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "https://api.truthlocks.com"
	}
	return &Client{BaseURL: baseURL}
}

// Verify checks a Truthlocks attestation ID with the public verification API.
// Transport failures and malformed responses never count as verification.
func (c *Client) Verify(attestationID string) (bool, error) {
	if strings.TrimSpace(attestationID) == "" {
		return false, fmt.Errorf("attestation ID is required")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return false, fmt.Errorf("invalid API base URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/verify"
	u.RawQuery, u.Fragment = "", ""
	body, _ := json.Marshal(map[string]string{"attestation_id": attestationID})
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := http.Client{Timeout: 30 * time.Second}
	if c.HTTPClient != nil {
		client = *c.HTTPClient
	}
	if client.Timeout == 0 {
		client.Timeout = 30 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("verification API returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Verdict string `json:"verdict"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return false, fmt.Errorf("invalid verification response: %w", err)
	}
	if result.Verdict == "" {
		return false, fmt.Errorf("verification response is missing verdict")
	}
	return result.Verdict == "VALID", nil
}
