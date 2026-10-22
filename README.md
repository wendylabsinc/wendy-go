# WendyGo

The Wendy SDK for Go, built on [Wendy Core](https://github.com/wendylabsinc/wendy-core).

```go
import "github.com/wendylabsinc/wendy-go"

value := wendy.HelloWorld() // 42, computed by Wendy Core
version := wendy.CoreVersion() // version of the linked Wendy Core engine
```

WendyGo is the Go API for Wendy's own programs (the CLI and the Agent) as well as third-party Go code. It calls Wendy Core's Go API (`github.com/wendylabsinc/wendy-core/core`) directly, not through Core's C interface, and needs no cgo. Shared behavior belongs in Wendy Core, so a fix there reaches every client and language. This SDK adds Go conveniences on top, not separate product behavior.

This is a scaffold: `HelloWorld()` is a temporary operation that proves the SDK reaches the shared engine. Real APIs move in step by step.

## Wendy Core dependency

`CoreVersion()` reports Wendy Core's version directly, so clients do not need to
duplicate the engine's version string. This seed reports `0.1.0-seed.1`.

`go.mod` requires Wendy Core `v0.1.0-seed.1`.

For the WendyGo seed release, request the pre-release explicitly:

```sh
go get github.com/wendylabsinc/wendy-go@v0.1.0-seed.1
```

`@latest` selects the stable `v0.0.1` release instead of the seed pre-release.
To select this seed of Wendy Core directly:

```sh
go get github.com/wendylabsinc/wendy-core@v0.1.0-seed.1
go mod tidy
```

## Development

Requires Go 1.24+.

```sh
go vet ./...
go test ./...
```

## License

Apache License 2.0; see [LICENSE](LICENSE).
