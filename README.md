# WendyGo

The Wendy SDK for Go, built on [Wendy Core](https://github.com/wendylabsinc/wendy-core).

```go
import "github.com/wendylabsinc/wendy-go"

value := wendy.HelloWorld() // 42, computed by Wendy Core
```

WendyGo is the Go API for Wendy's own programs (the CLI and the Agent) as well as third-party Go code. It calls Wendy Core's Go API (`github.com/wendylabsinc/wendy-core/core`) directly, not through Core's C interface, and needs no cgo. Shared behavior belongs in Wendy Core, so a fix there reaches every client and language. This SDK adds Go conveniences on top, not separate product behavior.

This is a scaffold: `HelloWorld()` is a temporary operation that proves the SDK reaches the shared engine. Real APIs move in step by step.

## Wendy Core dependency

Until Wendy Core publishes releases, `go.mod` pins a Core commit as a pseudo-version. To update it:

```sh
go get github.com/wendylabsinc/wendy-core@main
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
