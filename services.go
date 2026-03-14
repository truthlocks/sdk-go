package truthlock

import (
	"context"
)

// IssuersService provides issuer management operations.
type IssuersService struct {
	client *Client
}

// Create creates a new issuer.
func (s *IssuersService) Create(ctx context.Context, req *CreateIssuerRequest) (*Issuer, error) {
	var issuer Issuer
	if err := s.client.request(ctx, "POST", "/v1/issuers", req, &issuer); err != nil {
		return nil, err
	}
	return &issuer, nil
}

// Get retrieves an issuer by ID.
func (s *IssuersService) Get(ctx context.Context, id string) (*Issuer, error) {
	var issuer Issuer
	if err := s.client.request(ctx, "GET", "/v1/issuers/"+id, nil, &issuer); err != nil {
		return nil, err
	}
	return &issuer, nil
}

// List retrieves all issuers for the current tenant.
func (s *IssuersService) List(ctx context.Context) ([]*Issuer, error) {
	var issuers []*Issuer
	if err := s.client.request(ctx, "GET", "/v1/issuers", nil, &issuers); err != nil {
		return nil, err
	}
	return issuers, nil
}

// Trust approves and trusts an issuer.
func (s *IssuersService) Trust(ctx context.Context, id string) (*Issuer, error) {
	var issuer Issuer
	if err := s.client.request(ctx, "POST", "/v1/issuers/"+id+"/trust", nil, &issuer); err != nil {
		return nil, err
	}
	return &issuer, nil
}

// Suspend suspends an issuer.
func (s *IssuersService) Suspend(ctx context.Context, id string, reason string) (*Issuer, error) {
	var issuer Issuer
	body := map[string]string{"reason": reason}
	if err := s.client.request(ctx, "POST", "/v1/issuers/"+id+"/suspend", body, &issuer); err != nil {
		return nil, err
	}
	return &issuer, nil
}

// Revoke revokes an issuer.
func (s *IssuersService) Revoke(ctx context.Context, id string, reason string) (*Issuer, error) {
	var issuer Issuer
	body := map[string]string{"reason": reason}
	if err := s.client.request(ctx, "POST", "/v1/issuers/"+id+"/revoke", body, &issuer); err != nil {
		return nil, err
	}
	return &issuer, nil
}

// KeysService provides key management operations.
type KeysService struct {
	client *Client
}

// Register registers a new signing key for an issuer.
func (s *KeysService) Register(ctx context.Context, issuerID string, req *RegisterKeyRequest) (*IssuerKey, error) {
	var key IssuerKey
	if err := s.client.request(ctx, "POST", "/v1/issuers/"+issuerID+"/keys", req, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// List retrieves all keys for an issuer.
func (s *KeysService) List(ctx context.Context, issuerID string) ([]*IssuerKey, error) {
	var keys []*IssuerKey
	if err := s.client.request(ctx, "GET", "/v1/issuers/"+issuerID+"/keys", nil, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// AttestationsService provides attestation operations.
type AttestationsService struct {
	client *Client
}

// Mint creates a new attestation.
func (s *AttestationsService) Mint(ctx context.Context, req *MintRequest) (*Attestation, error) {
	var attestation Attestation
	if err := s.client.request(ctx, "POST", "/v1/attestations", req, &attestation); err != nil {
		return nil, err
	}
	return &attestation, nil
}

// Get retrieves an attestation by ID.
func (s *AttestationsService) Get(ctx context.Context, id string) (*Attestation, error) {
	var attestation Attestation
	if err := s.client.request(ctx, "GET", "/v1/attestations/"+id, nil, &attestation); err != nil {
		return nil, err
	}
	return &attestation, nil
}

// Revoke revokes an attestation.
func (s *AttestationsService) Revoke(ctx context.Context, id string, req *RevokeRequest) (*Attestation, error) {
	var attestation Attestation
	if err := s.client.request(ctx, "POST", "/v1/attestations/"+id+"/revoke", req, &attestation); err != nil {
		return nil, err
	}
	return &attestation, nil
}

// GetProofBundle retrieves the proof bundle for an attestation.
func (s *AttestationsService) GetProofBundle(ctx context.Context, id string) (*ProofBundle, error) {
	var bundle ProofBundle
	if err := s.client.request(ctx, "GET", "/v1/attestations/"+id+"/proof-bundle", nil, &bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

// VerifyService provides verification operations.
type VerifyService struct {
	client *Client
}

// VerifyOnline verifies an attestation online.
func (s *VerifyService) VerifyOnline(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	var resp VerifyResponse
	if err := s.client.request(ctx, "POST", "/v1/verify", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AuditService provides audit log operations.
type AuditService struct {
	client *Client
}

// QueryEvents queries audit events with optional filters.
func (s *AuditService) QueryEvents(ctx context.Context, params map[string]string) ([]*AuditEvent, error) {
	var events []*AuditEvent
	// Note: In full implementation, params would be added as query string
	if err := s.client.request(ctx, "GET", "/v1/audit/events", nil, &events); err != nil {
		return nil, err
	}
	return events, nil
}
