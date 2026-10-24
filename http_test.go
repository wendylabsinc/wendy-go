package wendy_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wendy "github.com/wendylabsinc/wendy-go"
)

func TestHTTPTransportTLSAndOwnership(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, []byte("request\x00\xff")) || r.Method != "POST" || r.Header.Get("Authorization") != "DPoP token" || r.Header.Get("DPoP") != "proof" {
			t.Error("HTTP request data changed")
		}
		if got := r.Header.Values("X-Repeated"); len(got) != 2 || got[0] != "first" || got[1] != "second" {
			t.Error("repeated headers changed")
		}
		w.Header().Add("X-Repeated", "one")
		w.Header().Add("X-Repeated", "two")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("response\x00\xff"))
	}))
	defer server.Close()
	transport, err := wendy.NewHTTPTransport(server.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := wendy.HTTPRequest{Method: "POST", URL: server.URL, Headers: wendy.HTTPHeaders{
		"authorization": {"DPoP token"}, "dpop": {"proof"}, "X-Repeated": {"first", "second"},
	}, Body: []byte("request\x00\xff")}
	response, err := transport.Do(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusUnauthorized || !bytes.Equal(data, []byte("response\x00\xff")) {
		t.Fatalf("response changed: status %d, err %v", response.StatusCode, err)
	}
	if got := response.Headers["X-Repeated"]; len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatal("response headers changed")
	}
	if request.Headers.Get("authorization") != "DPoP token" || !bytes.Equal(request.Body, []byte("request\x00\xff")) {
		t.Fatal("borrowed request was mutated")
	}
}

func TestHTTPTransportNeverFollowsRedirectsOrRetries(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationCalls.Add(1)
	}))
	defer destination.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		for _, crossOrigin := range []bool{false, true} {
			t.Run(strconv.Itoa(code)+"/cross-origin="+strconv.FormatBool(crossOrigin), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					target := "/redirected"
					if crossOrigin {
						target = destination.URL
					}
					http.Redirect(w, r, target, code)
				}))
				defer server.Close()
				client := server.Client()
				var customRedirect atomic.Int32
				client.CheckRedirect = func(*http.Request, []*http.Request) error { customRedirect.Add(1); return nil }
				transport, err := wendy.NewHTTPTransport(client)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := transport.Do(context.Background(), wendy.HTTPRequest{Method: "POST", URL: server.URL, Headers: wendy.HTTPHeaders{
					"Authorization": {"DPoP credential"}, "DPoP": {"target-bound-proof"},
				}, Body: []byte("refresh_token=secret")})
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != code || calls.Load() != 1 || destinationCalls.Load() != 0 || customRedirect.Load() != 0 {
					t.Fatal("redirect followed or request retried")
				}
				// Construction must not replace the caller's redirect policy.
				_ = client.CheckRedirect(nil, nil)
				if customRedirect.Load() != 1 {
					t.Fatal("caller client mutated")
				}
			})
		}
	}
}

type httpRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f httpRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPTransportRefusesInvalidRequestsAndRedactsErrors(t *testing.T) {
	if _, err := wendy.NewHTTPTransport(nil); err == nil {
		t.Fatal("accepted nil client")
	}
	var calls atomic.Int32
	transport, err := wendy.NewHTTPTransport(&http.Client{Transport: httpRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.GetBody != nil {
			t.Error("body replay available")
		}
		return nil, errors.New("failure containing sensitive-request-data")
	})})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []wendy.HTTPRequest{
		{URL: ":sensitive-request-data"}, {Method: "bad\nmethod", URL: "https://example.test"},
		{URL: "/relative"}, {URL: "ftp://example.test"}, {URL: "https://user:sensitive-request-data@example.test"},
		{URL: "https://example.test/#fragment"},
		{URL: "https://example.test", Headers: wendy.HTTPHeaders{"invalid header": {"secret"}}},
		{URL: "https://example.test", Headers: wendy.HTTPHeaders{"X-Test": {"sensitive-request-data\r\nInjected: secret"}}},
	} {
		response, err := transport.Do(context.Background(), req)
		if response != nil || err == nil || strings.Contains(err.Error(), "sensitive-request-data") {
			t.Fatalf("invalid request response: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached transport")
	}
	resp, err := transport.Do(context.Background(), wendy.HTTPRequest{Method: "POST", URL: "https://example.test/?secret=sensitive-request-data", Body: []byte("secret")})
	if resp != nil || err == nil || strings.Contains(err.Error(), "sensitive-request-data") || calls.Load() != 1 {
		t.Fatalf("network error was leaked or retried: %v", err)
	}
}

func TestHTTPTransportCancellationAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/body" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 50 * time.Millisecond
	transport, err := wendy.NewHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := transport.Do(context.Background(), wendy.HTTPRequest{URL: server.URL}); resp != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("client timeout: %v", err)
	}
	client.Timeout = 0
	transport, err = wendy.NewHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if resp, err := transport.Do(ctx, wendy.HTTPRequest{URL: server.URL}); resp != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled request: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	resp, err := transport.Do(ctx, wendy.HTTPRequest{URL: server.URL + "/body"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cancel()
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, context.Canceled) {
		t.Fatalf("body did not retain cancellation: %v", err)
	}
}
