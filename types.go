package truthlock

import "time"

// Algorithm represents cryptographic signing algorithm identifiers (JOSE standard names).
type Algorithm string

const (
	// ECDSA algorithms
	AlgES256 Algorithm = "ES256" // ECDSA P-256 + SHA-256
	AlgES384 Algorithm = "ES384" // ECDSA P-384 + SHA-384
	AlgES512 Algorithm = "ES512" // ECDSA P-521 + SHA-512

	// RSA PKCS#1 v1.5 algorithms
	AlgRS256 Algorithm = "RS256" // RSASSA-PKCS1-v1_5 + SHA-256
	AlgRS384 Algorithm = "RS384" // RSASSA-PKCS1-v1_5 + SHA-384
	AlgRS512 Algorithm = "RS512" // RSASSA-PKCS1-v1_5 + SHA-512

	// RSA-PSS algorithms
	AlgPS256 Algorithm = "PS256" // RSASSA-PSS + SHA-256
	AlgPS384 Algorithm = "PS384" // RSASSA-PSS + SHA-384
	AlgPS512 Algorithm = "PS512" // RSASSA-PSS + SHA-512

	// EdDSA algorithm
	AlgEd25519 Algorithm = "Ed25519" // EdDSA with Ed25519 curve

	// Deprecated: use AlgES256 instead. Kept for backward compatibility.
	AlgP256 Algorithm = "ES256"
	// Deprecated: use AlgES384 instead. Kept for backward compatibility.
	AlgP384 Algorithm = "ES384"
)

// supportedAlgorithms is the authoritative set of all supported signing algorithms.
var supportedAlgorithms = map[Algorithm]bool{
	AlgES256:   true,
	AlgES384:   true,
	AlgES512:   true,
	AlgRS256:   true,
	AlgRS384:   true,
	AlgRS512:   true,
	AlgPS256:   true,
	AlgPS384:   true,
	AlgPS512:   true,
	AlgEd25519: true,
}

// SupportedAlgorithms returns a slice of all supported signing algorithm identifiers.
func SupportedAlgorithms() []Algorithm {
	return []Algorithm{
		AlgES256,
		AlgES384,
		AlgES512,
		AlgRS256,
		AlgRS384,
		AlgRS512,
		AlgPS256,
		AlgPS384,
		AlgPS512,
		AlgEd25519,
	}
}

// IsValid returns true if the algorithm is one of the supported signing algorithms.
func (a Algorithm) IsValid() bool {
	return supportedAlgorithms[a]
}

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
	PublicKey    string     `json:"public_key,omitempty"`
	CanSign      bool       `json:"can_sign"`
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
	PayloadHashB64URL string `json:"payload_hash_b64url,omitempty"`
	SignatureB64URL   string `json:"signature_b64url,omitempty"`
	DocumentHashHex   string `json:"document_hash_hex,omitempty"`
	IssuedAtUnix      int64  `json:"issued_at_unix"`
	Signature         struct {
		Alg   string `json:"alg"`
		KID   string `json:"kid"`
		Value string `json:"value"`
	} `json:"signature"`
	Log struct {
		LogID     string `json:"log_id"`
		LeafIndex int64  `json:"leaf_index"`
		LeafHash  string `json:"leaf_hash"`
		ProofURL  string `json:"proof_url"`
	} `json:"log"`
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
	Schema         string                 `json:"schema,omitempty"`
	Claims         map[string]interface{} `json:"claims,omitempty"`
	ContentType    string                 `json:"content_type,omitempty"`
	DocumentHash   string                 `json:"document_hash,omitempty"`
	RecipientEmail string                 `json:"recipient_email,omitempty"`
	AttestationID  string                 `json:"attestation_id,omitempty"`
	PackID         string                 `json:"pack_id,omitempty"`
	IssuerID       string                 `json:"issuer_id"`
	KID            string                 `json:"kid"`
	Alg            Algorithm              `json:"alg"`
	PayloadB64URL  string                 `json:"payload_b64url,omitempty"`
}

// RevokeRequest is the request to revoke an attestation.
type RevokeRequest struct {
	Reason string `json:"reason"`
}

// VerifyRequest is the request to verify an attestation.
type VerifyRequest struct {
	DocumentHashHex string `json:"document_hash_hex,omitempty"`
	AttestationID   string `json:"attestation_id"`
	PayloadB64URL   string `json:"payload_b64url,omitempty"`
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
	LogID          string         `json:"log_id"`
	LeafIndex      int64          `json:"leaf_index"`
	LeafHash       string         `json:"leaf_hash"`
	InclusionProof InclusionProof `json:"inclusion_proof"`
	Checkpoint     Checkpoint     `json:"checkpoint"`
}

type InclusionProof struct {
	LeafIndex       int64    `json:"leaf_index"`
	LeafHashB64URL  string   `json:"leaf_hash_b64url"`
	AuditPathB64URL []string `json:"audit_path_b64url"`
	HashAlg         string   `json:"hash_alg"`
}

// Checkpoint contains signed tree head data.
type Checkpoint struct {
	RootHashB64URL         string    `json:"root_hash_b64url"`
	IssuedAt               time.Time `json:"issued_at"`
	SignatureB64URL        string    `json:"signature_b64url"`
	SignerKID              string    `json:"signer_kid"`
	SigningPublicKeyB64URL string    `json:"signing_pubkey_b64url"`
	SignatureAlg           string    `json:"signature_alg"`
	TreeSize               int64     `json:"tree_size"`
	RootHash               string    `json:"root_hash"`
	Timestamp              time.Time `json:"timestamp"`
	Signature              string    `json:"signature"`
	SigKID                 string    `json:"sig_kid"`
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

// ============================================================================
// Receipt Types (Ticket 81: Receipt Canonical Event Schema v2)
// ============================================================================

// ReceiptStatus represents the lifecycle status of a receipt event.
type ReceiptStatus string

const (
	ReceiptStatusActive     ReceiptStatus = "active"
	ReceiptStatusRevoked    ReceiptStatus = "revoked"
	ReceiptStatusSuperseded ReceiptStatus = "superseded"
)

// RetentionPolicy controls how long receipt data is retained.
type RetentionPolicy string

const (
	RetentionPolicyStandard  RetentionPolicy = "standard"
	RetentionPolicyExtended  RetentionPolicy = "extended"
	RetentionPolicyPermanent RetentionPolicy = "permanent"
)

// ReceiptTypeStatus represents the lifecycle of a receipt type definition.
type ReceiptTypeStatus string

const (
	ReceiptTypeStatusActive     ReceiptTypeStatus = "active"
	ReceiptTypeStatusDeprecated ReceiptTypeStatus = "deprecated"
	ReceiptTypeStatusArchived   ReceiptTypeStatus = "archived"
)

// ReceiptType describes a versioned receipt family registered in the platform.
type ReceiptType struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	DisplayName string                 `json:"display_name"`
	Version     string                 `json:"version"`
	Status      ReceiptTypeStatus      `json:"status"`
	Schema      map[string]interface{} `json:"schema"`
	Description string                 `json:"description,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// ReceiptSignature contains the cryptographic signature for a receipt event.
type ReceiptSignature struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Value string `json:"value"`
}

// ReceiptLog contains transparency log anchoring details for a receipt.
type ReceiptLog struct {
	LogID     string `json:"log_id"`
	LeafIndex int64  `json:"leaf_index"`
	LeafHash  string `json:"leaf_hash"`
}

// ReceiptEvent represents a minted, signed, and log-anchored receipt.
type ReceiptEvent struct {
	ReceiptID      string           `json:"receipt_id"`
	ReceiptType    string           `json:"receipt_type"`
	ReceiptVersion string           `json:"receipt_version"`
	Status         ReceiptStatus    `json:"status"`
	IssuedAt       string           `json:"issued_at"`
	TenantID       string           `json:"tenant_id"`
	IssuerID       string           `json:"issuer_id"`
	PayloadHash    string           `json:"payload_hash"`
	Signature      ReceiptSignature `json:"signature"`
	Log            ReceiptLog       `json:"log"`
}

// MintReceiptRequest is the request to create a new receipt event.
type MintReceiptRequest struct {
	IssuerID        string                 `json:"issuer_id"`
	KID             string                 `json:"kid"`
	Alg             string                 `json:"alg"`
	ReceiptType     string                 `json:"receipt_type"`
	ReceiptVersion  string                 `json:"receipt_version,omitempty"`
	Subject         string                 `json:"subject"`
	Payload         map[string]interface{} `json:"payload"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	RetentionPolicy RetentionPolicy        `json:"retention_policy,omitempty"`
}

// RevokeReceiptRequest is the optional body for revoking a receipt.
type RevokeReceiptRequest struct {
	Reason string `json:"reason,omitempty"`
}

// ListReceiptsFilter contains optional query filters for listing receipts.
type ListReceiptsFilter struct {
	ReceiptType string
	IssuerID    string
	Status      ReceiptStatus
	Limit       int
	Offset      int
}

// ListReceiptsResponse contains a paginated list of receipt events.
type ListReceiptsResponse struct {
	Items  []ReceiptEvent `json:"items"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

// ListReceiptTypesResponse contains the available receipt type families.
type ListReceiptTypesResponse struct {
	Items []ReceiptType `json:"items"`
	Total int           `json:"total"`
}

// CreateReceiptTypeRequest is the request to create a tenant-custom receipt type.
type CreateReceiptTypeRequest struct {
	Name        string                 `json:"name"`
	DisplayName string                 `json:"display_name"`
	Version     string                 `json:"version,omitempty"`
	Schema      map[string]interface{} `json:"schema"`
	Description string                 `json:"description,omitempty"`
}

// UpdateReceiptTypeRequest is used to deprecate or archive a receipt type.
type UpdateReceiptTypeRequest struct {
	Status string `json:"status"` // deprecated | archived
}

// SigningPolicy governs which issuers and algorithms may mint a receipt type.
type SigningPolicy struct {
	ReceiptType      string   `json:"receipt_type"`
	Version          string   `json:"version"`
	PolicyConfigured bool     `json:"policy_configured"`
	AllowAnyIssuer   bool     `json:"allow_any_issuer"`
	AllowedIssuerIDs []string `json:"allowed_issuer_ids"`
	MinTrustTier     string   `json:"min_trust_tier"`
	AllowedAlgs      []string `json:"allowed_algs"`
	UpdatedAt        string   `json:"updated_at,omitempty"`
}

// SetSigningPolicyRequest sets the signing policy for a receipt type.
type SetSigningPolicyRequest struct {
	AllowAnyIssuer   bool     `json:"allow_any_issuer"`
	AllowedIssuerIDs []string `json:"allowed_issuer_ids,omitempty"`
	MinTrustTier     string   `json:"min_trust_tier,omitempty"`
	AllowedAlgs      []string `json:"allowed_algs,omitempty"`
}

// ReceiptVerifyResponse is the response from receipt verification.
type ReceiptVerifyResponse struct {
	Verdict     string `json:"verdict"`
	ReceiptID   string `json:"receipt_id"`
	ReceiptType string `json:"receipt_type"`
	IssuedAt    string `json:"issued_at,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// SearchReceiptsQuery supports full-text + faceted search.
type SearchReceiptsQuery struct {
	Query       string `json:"q,omitempty"`
	ReceiptType string `json:"receipt_type,omitempty"`
	Status      string `json:"status,omitempty"`
	IssuerID    string `json:"issuer_id,omitempty"`
	FromDate    string `json:"from_date,omitempty"`
	ToDate      string `json:"to_date,omitempty"`
	IndexKey    string `json:"index_key,omitempty"`
	IndexValue  string `json:"index_value,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Offset      int    `json:"offset,omitempty"`
}

// ReceiptExport represents an async bulk export job.
type ReceiptExport struct {
	ExportID     string `json:"export_id"`
	TenantID     string `json:"tenant_id"`
	Status       string `json:"status"`
	Format       string `json:"format"`
	CreatedAt    string `json:"created_at"`
	CompletedAt  string `json:"completed_at,omitempty"`
	RecordCount  int64  `json:"record_count,omitempty"`
	DownloadURL  string `json:"download_url,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// CreateExportRequest is the request to queue a receipt export.
type CreateExportRequest struct {
	Format  string                 `json:"format"`
	Filters map[string]interface{} `json:"filters,omitempty"`
}
