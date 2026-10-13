# Truthlocks Go SDK

Authenticated Go client for the Truthlocks API. Requires Go 1.22 or later.

## Install

```sh
go get github.com/truthlocks/sdk-go@latest
```

## Verify an existing record

Set `TRUTHLOCKS_API_KEY` to a workspace API key and `TRUTHLOCKS_ATTESTATION_ID`
to an existing record ID in the same environment. Never put credentials in source control.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    truthlock "github.com/truthlocks/sdk-go"
)

func main() {
    client := truthlock.NewClient(truthlock.Config{
        APIKey: os.Getenv("TRUTHLOCKS_API_KEY"),
    })
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    result, err := client.Verify.VerifyOnline(ctx, &truthlock.VerifyRequest{
        AttestationID: os.Getenv("TRUTHLOCKS_ATTESTATION_ID"),
    })
    if err != nil { log.Fatal(err) }
    fmt.Println(result.Verdict)
}
```

A `tl_test_` key selects `https://sandbox-api.truthlocks.com` by default.
Other keys select `https://api.truthlocks.com`. Set `BaseURL` explicitly to override.
`TenantID` alone does not authenticate; the server determines the workspace from
`APIKey` or `BearerToken`. Staff-only issuer governance requires an authorized staff
bearer identity and is not available to ordinary workspace API keys.

## Verify the original signature

An ID-only lookup returns `VerdictIncomplete` and `Valid == false` when no original signed bytes were supplied. It must not be treated as a verified signature. To perform that check, supply the exact payload bytes:

```go
// This excerpt continues the client/context setup above; import encoding/base64.
checked, err := client.Verify.VerifyOnline(ctx, &truthlock.VerifyRequest{
    AttestationID: os.Getenv("TRUTHLOCKS_ATTESTATION_ID"),
    PayloadB64URL: base64.RawURLEncoding.EncodeToString(payloadBytes),
})
if err != nil { log.Fatal(err) }
fmt.Println(checked.Verdict, checked.SignatureVerified, checked.Reasons)
```

`payloadBytes` must contain the original signed payload, which may be an envelope rather than an uploaded document. A matching file fingerprint alone does not check its signature. `ExpiresAtUnix == nil` means no signed expiry is recorded; historical records are not assigned a new expiry. A valid signature does not prove the truth of every claim.

## Mint with an existing signing key

Use an active issuer and a key that the console shows as available for signing.
Registering only a public key does not provide the service with its private key.

```go
ctx = truthlock.WithIdempotencyKey(ctx, "unique-key-for-this-one-request")
record, err := client.Attestations.Mint(ctx, &truthlock.MintRequest{
    IssuerID: issuerID,
    KID: signingKeyID,
    Alg: truthlock.AlgEd25519,
    PayloadB64URL: base64.RawURLEncoding.EncodeToString(payloadBytes),
})
```

This excerpt assumes `client`, `ctx`, `issuerID`, `signingKeyID`, and `payloadBytes`
are defined; import `encoding/base64`. Select the algorithm matching the signing key.
Retain the idempotency key and identical body when retrying a mint. A new key means
a new request. The Go client does not automatically retry writes.

## Available resources

- `Issuers.Create`, `Get`, `List`, and `Trust` manage workspace issuers.
- `Keys.Register` and `List` manage public verification keys.
- `Attestations.Mint`, `Get`, `Revoke`, and `GetProofBundle` handle records.
- `Verify.VerifyOnline` returns the server verdict and derives `Valid` from `VALID`.
- `Audit.QueryEvents` passes query filters to the audit API.
- `Receipts` provides receipt operations; availability depends on the deployed API,
  workspace permissions, and storage configuration.

A downloaded proof bundle is evidence, not an offline verification result. Use the
Truthlocks CLI with independently trusted issuer and log keys for offline checks.
The compatibility `pkg.Client.Verify` also performs online verification; it does not
return true without checking a server verdict.

## Errors and deadlines

Methods accept `context.Context`. The default HTTP timeout is 30 seconds; set
`HTTPClient` to customize it. Redirects are rejected to keep credentials on the
configured origin. Errors from non-successful HTTP responses use `*truthlock.TruthlockError`
with `Status`, `Code`, and `Message`; use `errors.As` to inspect them.

[API documentation](https://docs.truthlocks.com) · [Issues](https://github.com/truthlocks/sdk-go/issues)
