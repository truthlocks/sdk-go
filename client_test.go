package truthlock

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportMintAndAuditQuery(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-API-Key") != "test-fixture" || r.Header.Get("X-Tenant-ID") != "" {
			t.Error("invalid authentication headers")
		}
		if r.Method == "POST" {
			if r.Header.Get("Idempotency-Key") != "retained-key" {
				t.Error("missing retained key")
			}
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["payload_b64url"] != "e30" {
				t.Error("invalid JSON payload")
			}
			w.WriteHeader(201)
			w.Write([]byte(`{"attestation_id":"record-1","issued_at_unix":1700000000}`))
		} else {
			if r.URL.Query().Get("event_type") != "a&b" {
				t.Error("query was not encoded")
			}
			w.Write([]byte(`[]`))
		}
	}))
	defer server.Close()
	client := NewClient(Config{BaseURL: server.URL, APIKey: "test-fixture", TenantID: "ignored"})
	record, err := client.Attestations.Mint(WithIdempotencyKey(context.Background(), "retained-key"), &MintRequest{PayloadB64URL: "e30"})
	if err != nil || record.AttestationID != "record-1" {
		t.Fatalf("mint: %v, %v", record, err)
	}
	if _, err := client.Audit.QueryEvents(context.Background(), map[string]string{"event_type": "a&b"}); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestTransportErrorsAndEmptyResponse(t *testing.T) {
	for _, tc := range []struct {
		status    int
		body      string
		wantError bool
	}{
		{204, "", false}, {200, "not-json", true}, {403, `{"code":"FORBIDDEN","message":"Role required"}`, true},
	} {
		t.Run(http.StatusText(tc.status)+tc.body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }))
			defer server.Close()
			var result map[string]interface{}
			err := NewClient(Config{BaseURL: server.URL, APIKey: "test-fixture"}).request(context.Background(), "GET", "/v1/test", nil, &result)
			if (err != nil) != tc.wantError {
				t.Fatalf("error: %v", err)
			}
			if tc.status == 403 {
				var apiErr *TruthlockError
				if !errors.As(err, &apiErr) || apiErr.Status != 403 || apiErr.Code != ErrForbidden {
					t.Fatalf("wrong typed error: %v", err)
				}
			}
		})
	}
}

func TestTransportRefusesCredentialRedirectAndTenantOnly(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer source.Close()
	client := NewClient(Config{BaseURL: source.URL, APIKey: "test-fixture"})
	if err := client.request(context.Background(), "GET", "/", nil, nil); err == nil {
		t.Fatal("redirect accepted")
	}
	if leaked {
		t.Fatal("redirect followed")
	}
	if err := client.request(context.Background(), "GET", target.URL, nil, nil); err == nil {
		t.Fatal("absolute request accepted")
	}
	if err := NewClient(Config{BaseURL: source.URL, TenantID: "tenant"}).request(context.Background(), "GET", "/", nil, nil); err == nil {
		t.Fatal("tenant-only auth accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.request(ctx, "GET", "/", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation lost: %v", err)
	}
}

func TestTrustReadsCompleteIssuer(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == "POST" {
			w.Write([]byte(`{"issuer_id":"fixture","status":"trusted"}`))
		} else {
			w.Write([]byte(`{"id":"fixture","name":"QA","status":"trusted"}`))
		}
	}))
	defer server.Close()
	issuer, err := NewClient(Config{BaseURL: server.URL, APIKey: "fixture"}).Issuers.Trust(context.Background(), "fixture")
	if err != nil || issuer.ID != "fixture" || issuer.Name != "QA" || calls != 2 {
		t.Fatalf("issuer=%+v err=%v calls=%d", issuer, err, calls)
	}
}

func TestStructuredMintOmitsEncodedPayload(t *testing.T) {
	req := MintRequest{IssuerID: "issuer", KID: "key", Alg: AlgEd25519, Schema: "attestation", Claims: map[string]interface{}{"subject": "QA"}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["payload_b64url"]; exists {
		t.Fatal("encoded payload conflicts with structured input")
	}
	if body["schema"] != "attestation" {
		t.Fatal("structured schema lost")
	}
}
