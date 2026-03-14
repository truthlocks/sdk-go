# Truthlock Go SDK

Official Go SDK for the [Truthlocks](https://truthlocks.com) cryptographic trust infrastructure.

## Installation

```bash
go get github.com/truthlocks/sdk-go@latest
```

## Quick Start

```go
package main

import (
    "context"
    "encoding/base64"
    "fmt"

    truthlock "github.com/truthlocks/sdk-go"
)

func main() {
    client := truthlock.NewClient(truthlock.Config{
        BaseURL:  "https://api.truthlocks.com",
        TenantID: "your-tenant-id",
    })

    ctx := context.Background()

    // Create an issuer
    issuer, err := client.Issuers.Create(ctx, &truthlock.CreateIssuerRequest{
        Name:        "My Organization",
        LegalName:   "My Organization Inc.",
        DisplayName: "My Org",
    })
    if err != nil {
        panic(err)
    }

    // Mint an attestation
    attestation, err := client.Attestations.Mint(ctx, &truthlock.MintRequest{
        IssuerID:      issuer.ID,
        KID:           "key-1",
        Alg:           truthlock.AlgEd25519,
        PayloadB64URL: base64.RawURLEncoding.EncodeToString([]byte("Hello World")),
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("Attestation ID:", attestation.AttestationID)
}
```

## Requirements

- Go 1.22 or later

## Documentation

Full documentation: [docs.truthlocks.com/sdk/go](https://docs.truthlocks.com/sdk/go)

## License

MIT
