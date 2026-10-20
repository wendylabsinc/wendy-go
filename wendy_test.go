package wendy_test

import (
	"fmt"
	"testing"

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
