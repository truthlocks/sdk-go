package truthlock

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCurrentProofBundleShape(t *testing.T) {
	var bundle ProofBundle
	err := json.Unmarshal([]byte(`{"bundle_version":"v1","attestation":{"payload_hash_b64url":"hash","signature_b64url":"signature"},"transparency_log":{"log_id":"log","inclusion_proof":{"leaf_index":4,"leaf_hash_b64url":"leaf","audit_path_b64url":["sibling"],"hash_alg":"SHA-256"},"checkpoint":{"tree_size":5,"root_hash_b64url":"root","signature_alg":"Ed25519","signing_pubkey_b64url":"public-key","issued_at":"2026-10-08T00:00:00Z"}}}`), &bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.TransparencyLog.InclusionProof.LeafIndex != 4 || bundle.TransparencyLog.Checkpoint.SigningPublicKeyB64URL != "public-key" || bundle.Attestation.SignatureB64URL != "signature" {
		t.Fatalf("bundle fields were discarded: %+v", bundle)
	}
}

func TestVerifyValidityDerivedFromVerdict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"verdict":"VALID"}`)) }))
	defer server.Close()
	result, err := NewClient(Config{BaseURL: server.URL, APIKey: "fixture"}).Verify.VerifyOnline(context.Background(), &VerifyRequest{AttestationID: "record"})
	if err != nil || !result.Valid {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}
