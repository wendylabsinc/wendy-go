package wendy_test

import (
	"fmt"
	"testing"

	"github.com/wendylabsinc/wendy-core/core"
	"github.com/wendylabsinc/wendy-go"
)

func TestHelloWorldReachesCore(t *testing.T) {
	if got := wendy.HelloWorld(); got != 42 {
		t.Fatalf("HelloWorld() = %d, want 42", got)
	}
}

func ExampleHelloWorld() {
	fmt.Println(wendy.HelloWorld())
	// Output: 42
}

func TestCoreVersionReachesCore(t *testing.T) {
	if got, want := wendy.CoreVersion(), core.Version(); got != want || got == "" {
		t.Fatalf("CoreVersion() = %q, want non-empty Core version %q", got, want)
	}
}

func ExampleCoreVersion() {
	fmt.Printf("Wendy Core: %s\n", wendy.CoreVersion())
}
