// Package wendy is the Wendy SDK for Go.
//
// It builds on Wendy Core's Go API, github.com/wendylabsinc/wendy-core/core,
// which it calls directly, without going through Core's C interface. The SDK
// adds Go conveniences, never its own product behavior: shared behavior lives
// in Wendy Core so that every client and language gets the same fixes.
package wendy

import "github.com/wendylabsinc/wendy-core/core"

// HelloWorld returns 42 from Wendy Core. It is a temporary operation that
// proves the SDK reaches the shared engine.
func HelloWorld() int32 {
	return core.WendyHelloWorld()
}
