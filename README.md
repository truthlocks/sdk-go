# Truthlocks Go SDK

Official Go SDK for the [Truthlocks](https://truthlocks.com) cryptographic trust infrastructure.

## Install

```bash
go get github.com/truthlocks/sdk-go
```

## Quick Start (Free — No Website Needed)

```go
package main

import (
    "context"
    "fmt"
    truthlocks "github.com/truthlocks/sdk-go"
)

func main() {
    // Register in one line — get instant API key
    result, _ := truthlocks.Register(context.Background(), "dev@example.com")
    fmt.Println("API Key:", result.APIKey)

    // Start protecting content
    client := truthlocks.NewClient(result.APIKey)
    att, _ := client.Attestations.Mint(context.Background(), truthlocks.MintParams{
        ContentHash: "sha256:abc123...",
        Algorithm:   truthlocks.AlgEd25519,
    })
    fmt.Println("Protected:", att.ID)
}
```

## Supported Algorithms

| Constant | Algorithm | Use Case |
|----------|-----------|----------|
| `AlgEd25519` | EdDSA | Default, fastest |
| `AlgES256` | ECDSA P-256 | Web standard |
| `AlgES384` | ECDSA P-384 | Government/CNSA |
| `AlgES512` | ECDSA P-521 | Maximum ECDSA |
| `AlgRS256` | RSA 3072-bit | Legacy PKI |
| `AlgRS384` | RSA SHA-384 | Higher RSA |
| `AlgRS512` | RSA SHA-512 | Maximum RSA |
| `AlgPS256` | RSA-PSS | Modern RSA |
| `AlgPS384` | RSA-PSS 384 | Higher PSS |
| `AlgPS512` | RSA-PSS 512 | Maximum PSS |

## Free Tier

- 100 attestations/month
- 1,000 verifications/month
- No credit card required

Upgrade at [console.truthlocks.com](https://console.truthlocks.com/upgrade)

## Docs

- [API Reference](https://docs.truthlocks.com/sdk/go)
- [Quickstart](https://docs.truthlocks.com/quickstart)
- [MAIP Guide](https://docs.truthlocks.com/guides/machine-identity)

## License

Apache 2.0
