package wendy

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"golang.org/x/net/http/httpguts"
)

// NetHTTPTransport supplies Core with HTTP over a caller-configured client.
// It is safe for concurrent use. The caller owns the underlying RoundTripper,
// TLS, proxy and cookie policy, and must not configure application retries or
// credential logging. The adapter adds no retries and never follows redirects:
// tokens, request bodies and target-bound DPoP proofs stay at their exact URL.
type NetHTTPTransport struct{ client http.Client }

var _ HTTPTransport = (*NetHTTPTransport)(nil)

// NewHTTPTransport copies client, sharing its Transport and Jar. It preserves
// the timeout but replaces CheckRedirect with a policy returning the original
// redirect response. Configure client before calling; later field changes do
// not affect the adapter. A nil client is refused.
func NewHTTPTransport(client *http.Client) (*NetHTTPTransport, error) {
	if client == nil {
		return nil, errors.New("HTTP transport requires a client")
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &NetHTTPTransport{client: copy}, nil
}

// Do sends one HTTP exchange. ctx remains attached through response-body reads;
// the caller must close the body. Status codes, including redirects and errors,
// are returned unchanged. Errors exclude URLs, credentials and remote details.
func (t *NetHTTPTransport) Do(ctx context.Context, request HTTPRequest) (*HTTPResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(bytes.Clone(request.Body)))
	if err != nil {
		return nil, errors.New("invalid HTTP request")
	}
	if (req.URL.Scheme != "http" && req.URL.Scheme != "https") || req.URL.Host == "" || req.URL.User != nil || req.URL.Fragment != "" {
		return nil, errors.New("invalid HTTP request URL")
	}
	// Do not provide the client's transport a body-replay capability.
	req.GetBody = nil
	for name, values := range request.Headers {
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, errors.New("invalid HTTP header name")
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, errors.New("invalid HTTP header value")
			}
			req.Header.Add(name, value)
		}
	}
	resp, err := t.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, errors.New("HTTP request failed")
	}
	return &HTTPResponse{StatusCode: resp.StatusCode, Headers: HTTPHeaders(resp.Header.Clone()), Body: resp.Body}, nil
}
