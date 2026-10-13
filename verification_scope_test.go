package truthlock

import (
	"encoding/json"
	"testing"
)

func TestVerificationLogPreservesMissingAndFirstLeaf(t *testing.T) {
	for _, tc := range []struct {
		wire    string
		missing bool
	}{{`{"verdict":"INCOMPLETE","signature_verified":false,"log":{"leaf_index":null,"proof_checked":false}}`, true}, {`{"verdict":"VALID","signature_verified":true,"log":{"leaf_index":0,"proof_checked":true}}`, false}} {
		var result VerifyResponse
		if err := json.Unmarshal([]byte(tc.wire), &result); err != nil {
			t.Fatal(err)
		}
		if result.Log == nil || (result.Log.LeafIndex == nil) != tc.missing {
			t.Fatal("missing proof and leaf zero were conflated")
		}
	}
}
