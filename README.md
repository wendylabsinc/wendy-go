# WendyGo

The Wendy SDK for Go, built on [Wendy Core](https://github.com/wendylabsinc/WendyOS/tree/main/go/wendy-core).

```go
import "github.com/wendylabsinc/wendy-go"

value := wendy.HelloWorld() // 42, computed by Wendy Core
version := wendy.CoreVersion() // version of the linked Wendy Core engine
```

WendyGo is the Go API for Wendy's own programs (the CLI and the Agent) as well as third-party Go code. It calls Wendy Core's Go API (`github.com/wendylabsinc/WendyOS/go/wendy-core/core`) directly, not through Core's C interface, and needs no cgo. Shared behavior belongs in Wendy Core, so a fix there reaches every client and language. This SDK adds Go conveniences on top, not separate product behavior.

`HelloWorld()` is a temporary operation that proves the SDK reaches the shared engine. `NewGRPCTransport` supplies Core with RPC networking over a caller-owned grpc-go connection, and `NewMLDSA65Signer` signs exact bytes with the CLI's Go ML-DSA-65 key type. The caller owns TLS, credentials, key storage and certificate renewal. Shared product APIs move in step by step.

## Wendy Core dependency

`CoreVersion()` reports Wendy Core's version directly, so clients do not need to
duplicate the engine's version string. Go pseudo-version dependencies report a
development version with the Core commit, such as `0.1.0-dev+ed99070`.

`go.mod` pins `github.com/wendylabsinc/WendyOS/go/wendy-core` to
`v0.0.0-20261024174425-05b83d7ec89d`. This is an unmerged commit from
[WendyOS #2499 — Add Core host signing and RPC capability contracts](https://github.com/wendylabsinc/WendyOS/pull/2499)
and will be re-pinned after that PR merges.

To select the same Core dependency directly:

```sh
go get github.com/wendylabsinc/WendyOS/go/wendy-core@v0.0.0-20261024174425-05b83d7ec89d
go mod tidy
```

## Development

Requires Go 1.27+ (for `crypto/mldsa`, matching the CLI's key type).

```sh
go build ./...
go vet ./...
go test ./...
```

## License

Apache License 2.0; see [LICENSE](LICENSE).
