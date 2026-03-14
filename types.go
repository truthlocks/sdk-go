package truthlock

import "time"

// Algorithm represents cryptographic algorithm identifiers.
type Algorithm string

const (
	AlgEd25519 Algorithm = "Ed25519"
	AlgP256    Algorithm = "P-256"
	AlgP384    Algorithm = "P-384"
)

// IssuerStatus represents issuer status in the trust registry.
type IssuerStatus string

const (
	IssuerStatusPending   IssuerStatus = "pending"
	IssuerStatusTrusted   IssuerStatus = "trusted"
	IssuerStatusSuspended IssuerStatus = "suspended"
	IssuerStatusRevoked   IssuerStatus = "revoked"
)

// TrustTier represents trust tier classification for issuers.
type TrustTier string

const (
	TrustTierSelfIssued      TrustTier = "self_issued"
	TrustTierVerifiedOrg     TrustTier = "verified_org"
	TrustTierRegulatedIssuer TrustTier = "regulated_issuer"
)

// RiskRating represents risk rating for issuers.
type RiskRating string

const (
	RiskRatingUnknown  RiskRating = "unknown"
	RiskRatingLow      RiskRating = "low"
	RiskRatingMedium   RiskRating = "medium"
	RiskRatingHigh     RiskRating = "high"
	RiskRatingCritical RiskRating = "critical"
)

// KeyStatus represents key status in the trust registry.
type KeyStatus string

const (
	KeyStatusActive      KeyStatus = "ACTIVE"
	KeyStatusDisabled    KeyStatus = "DISABLED"
	KeyStatusExpired     KeyStatus = "EXPIRED"
	KeyStatusCompromised KeyStatus = "COMPROMISED"
)

// AttestationStatus represents attestation status.
type AttestationStatus string

const (
	AttestationStatusActive     AttestationStatus = "ACTIVE"
	AttestationStatusRevoked    AttestationStatus = "REVOKED"
	AttestationStatusSuperseded AttestationStatus = "SUPERSEDED"
)

// Verdict represents verification verdict.
type Verdict string

const (
	VerdictValid            Verdict = "VALID"
	VerdictAltered          Verdict = "ALTERED"
	VerdictRevoked          Verdict = "REVOKED"
	VerdictKeyExpired       Verdict = "KEY_EXPIRED"
	VerdictKeyCompromised   Verdict = "KEY_COMPROMISED"
	VerdictSignatureInvalid Verdict = "SIGNATURE_INVALID"
	VerdictLogProofFailed   Verdict = "LOG_PROOF_FAILED"
)

// Issuer represents an issuer in the trust registry.
type Issuer struct {
	ID              string       `json:"id"`
	TenantID        string       `json:"tenant_id"`
	Name            string       `json:"name"`
	LegalName       string       `json:"legal_name"`
	DisplayName     string       `json:"display_name"`
	Jurisdiction    string       `json:"jurisdiction"`
	RegistrationRef string       `json:"registration_ref"`
	TrustTier       TrustTier    `json:"trust_tier"`
	Status          IssuerStatus `json:"status"`
	ApprovalMethod  string       `json:"approval_method"`
	StatusChangedAt time.Time    `json:"status_changed_at"`
	RiskRating      RiskRating   `json:"risk_rating"`
	AssuranceLevel  string       `json:"assurance_level"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

// CreateIssuerRequest is the request to create a new issuer.
type CreateIssuerRequest struct {
	Name            string `json:"name"`
	LegalName       string `json:"legal_name"`
	DisplayName     string `json:"display_name"`
	Jurisdiction    string `json:"jurisdiction,omitempty"`
	RegistrationRef string `json:"registration_ref,omitempty"`
	AssuranceLevel  string `json:"assurance_level,omitempty"`
}

// IssuerKey represents a signing key in the trust registry.
type IssuerKey struct {
	KID          string     `json:"kid"`
	IssuerID     string     `json:"issuer_id"`
	Alg          Algorithm  `json:"alg"`
	PublicKeyB64 string     `json:"public_key_b64url"`
	Status       KeyStatus  `json:"status"`
	ValidFrom    time.Time  `json:"valid_from"`
	ValidTo      *time.Time `json:"valid_to,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// RegisterKeyRequest is the request to register a new key.
type RegisterKeyRequest struct {
	KID          string     `json:"kid"`
	Alg          Algorithm  `json:"alg"`
	PublicKeyB64 string     `json:"public_key_b64url"`
	ValidFrom    *time.Time `json:"valid_from,omitempty"`
	ValidTo      *time.Time `json:"valid_to,omitempty"`
}

// Attestation represents an attestation.
type Attestation struct {
	AttestationID    string            `json:"attestation_id"`
	TenantID         string            `json:"tenant_id"`
	IssuerID         string            `json:"issuer_id"`
	KID              string            `json:"kid"`
	Alg              Algorithm         `json:"alg"`
	PayloadHash      string            `json:"payload_hash"`
	Status           AttestationStatus `json:"status"`
	IssuedAt         time.Time         `json:"issued_at"`
	RevokedAt        *time.Time        `json:"revoked_at,omitempty"`
	RevocationReason string            `json:"revocation_reason,omitempty"`
	SupersededBy     string            `json:"superseded_by,omitempty"`
	LogID            string            `json:"log_id"`
	LeafIndex        int64             `json:"leaf_index"`
}

// MintRequest is the request to mint a new attestation.
type MintRequest struct {
	IssuerID      string    `json:"issuer_id"`
	KID           string    `json:"kid"`
	Alg           Algorithm `json:"alg"`
	PayloadB64URL string    `json:"payload_b64url"`
}

// RevokeRequest is the request to revoke an attestation.
type RevokeRequest struct {
	Reason string `json:"reason"`
}

// VerifyRequest is the request to verify an attestation.
type VerifyRequest struct {
	AttestationID string `json:"attestation_id"`
	PayloadB64URL string `json:"payload_b64url"`
}

// VerifyResponse is the response from verification.
type VerifyResponse struct {
	Valid       bool         `json:"valid"`
	Verdict     Verdict      `json:"verdict"`
	Attestation *Attestation `json:"attestation,omitempty"`
	Issuer      *Issuer      `json:"issuer,omitempty"`
	Key         *IssuerKey   `json:"key,omitempty"`
	Governance  Governance   `json:"governance"`
	Errors      []string     `json:"errors,omitempty"`
}

// Governance contains governance disclosure information.
type Governance struct {
	IssuerStatus    IssuerStatus `json:"issuer_status"`
	IssuerTrustTier TrustTier    `json:"issuer_trust_tier"`
	KeyStatus       KeyStatus    `json:"key_status"`
}

// ProofBundle contains all data needed for offline verification.
type ProofBundle struct {
	BundleID         string          `json:"bundle_id"`
	BundleVersion    string          `json:"bundle_version"`
	GeneratedAt      time.Time       `json:"generated_at"`
	TenantID         string          `json:"tenant_id"`
	Attestation      Attestation     `json:"attestation"`
	IssuerCurrent    Issuer          `json:"issuer_current"`
	Key              IssuerKey       `json:"key"`
	TransparencyLog  TransparencyLog `json:"transparency_log"`
	Audit            BundleAudit     `json:"audit"`
	BundleHashB64URL string          `json:"bundle_hash_b64url"`
}

// TransparencyLog contains transparency log proof data.
type TransparencyLog struct {
	LogID          string     `json:"log_id"`
	LeafIndex      int64      `json:"leaf_index"`
	LeafHash       string     `json:"leaf_hash"`
	InclusionProof []string   `json:"inclusion_proof"`
	Checkpoint     Checkpoint `json:"checkpoint"`
}

// Checkpoint contains signed tree head data.
type Checkpoint struct {
	TreeSize  int64     `json:"tree_size"`
	RootHash  string    `json:"root_hash"`
	Timestamp time.Time `json:"timestamp"`
	Signature string    `json:"signature"`
	SigKID    string    `json:"sig_kid"`
}

// BundleAudit contains bundle audit metadata.
type BundleAudit struct {
	SourceEndpoints []string          `json:"source_endpoints"`
	ServiceVersions map[string]string `json:"service_versions"`
}

// AuditEvent represents an audit log event.
type AuditEvent struct {
	ID           string                 `json:"id"`
	TenantID     string                 `json:"tenant_id"`
	EventType    string                 `json:"event_type"`
	ActorID      string                 `json:"actor_id"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Action       string                 `json:"action"`
	Details      map[string]interface{} `json:"details"`
	Timestamp    time.Time              `json:"timestamp"`
}
