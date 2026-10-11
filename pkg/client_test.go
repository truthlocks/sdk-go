package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyUsesServerVerdict(t *testing.T) {
	for _, tc := range []struct {
		body           string
		status         int
		valid, wantErr bool
	}{
		{`{"verdict":"VALID"}`, 200, true, false},
		{`{"verdict":"ALTERED"}`, 200, false, false},
		{`{}`, 200, false, true},
		{`not json`, 200, false, true},
		{`{"verdict":"VALID"}`, 500, false, true},
	} {
		t.Run(tc.body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1/verify" {
					t.Errorf("wrong operation: %s %s", r.Method, r.URL.Path)
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["attestation_id"] != "record-id" {
					t.Error("incorrect verification request")
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()
			valid, err := NewClient(server.URL).Verify("record-id")
			if valid != tc.valid || (err != nil) != tc.wantErr {
				t.Fatalf("valid=%v err=%v", valid, err)
			}
		})
	}
}
