// Package cloudflare solves the Cloudflare WAF challenge with the Flash Solvers API.
//
// The API only generates each step. Every request to the protected site is made
// here, with a Chrome TLS fingerprint, your proxy and your cookie jar.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	nethttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const (
	// DefaultEndpoint is the Flash Solvers Cloudflare API.
	DefaultEndpoint = "https://cf.flashsolvers.com"
	// DefaultUserAgent is the browser the API emulates. Origin requests must use it.
	DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
	// DefaultMaxAttempts is how many solves are started before giving up.
	DefaultMaxAttempts = 3
	// ClearanceCookie is the cookie a solved challenge sets.
	ClearanceCookie = "cf_clearance"

	apiUserAgent = "flashsolvers-cloudflare-go/0.1.0"
)

// Config configures a Solver. Only APIKey is required.
type Config struct {
	APIKey string
	// Proxy is an http://, https:// or socks5:// URL used for every request to the site.
	Proxy string
	// Endpoint defaults to DefaultEndpoint.
	Endpoint string
	// UserAgent defaults to DefaultUserAgent and must match the API's browser profile.
	UserAgent string
	// MaxAttempts defaults to DefaultMaxAttempts.
	MaxAttempts int
	// Client, when set, is used for every request to the site instead of a new Chrome client
	// per solve. It must not follow redirects. Use it to keep one session and cookie jar.
	Client tls_client.HttpClient
	// APIClient is used for calls to the Flash Solvers API. It defaults to a client with a 60 second timeout.
	APIClient *nethttp.Client
}

// Result is a cleared challenge.
type Result struct {
	// Clearance is the cf_clearance cookie value.
	Clearance string
	// Cookies are all cookies in the jar for the solved URL, including cf_clearance.
	Cookies []*http.Cookie
	// UserAgent must be sent on every later request that uses the cookies.
	UserAgent string
	// Client is the session that solved the challenge. Keep using it, with the same proxy.
	Client tls_client.HttpClient
	// Attempts is how many solves were started.
	Attempts int
}

// Solver solves challenges. It is safe for concurrent use when Config.Client is nil.
type Solver struct {
	cfg Config
}

// New validates cfg and returns a Solver.
func New(cfg Config) (*Solver, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("cloudflare: APIKey is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEndpoint
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.APIClient == nil {
		cfg.APIClient = &nethttp.Client{Timeout: 60 * time.Second}
	}
	return &Solver{cfg: cfg}, nil
}

// NewClient returns a Chrome TLS client with a cookie jar that does not follow redirects,
// suitable for Config.Client.
func NewClient(proxy string) (tls_client.HttpClient, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_152),
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithDisableHttp3(),
		tls_client.WithTimeoutSeconds(60),
	}
	if proxy != "" {
		opts = append(opts, tls_client.WithProxyUrl(proxy))
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

// Solve clears the Cloudflare challenge on pageURL and returns the cf_clearance cookie.
func (s *Solver) Solve(ctx context.Context, pageURL string) (*Result, error) {
	page, err := url.Parse(pageURL)
	if err != nil || page.Host == "" {
		return nil, fmt.Errorf("cloudflare: invalid url %q", pageURL)
	}
	lastErr := ErrNotCleared
	for attempt := 1; attempt <= s.cfg.MaxAttempts; attempt++ {
		// A failed attempt taints its session, so each attempt gets a fresh client unless the caller supplied one.
		client := s.cfg.Client
		if client == nil {
			if client, err = NewClient(s.cfg.Proxy); err != nil {
				return nil, fmt.Errorf("cloudflare: create client: %w", err)
			}
		}
		clearance, retryAfter, err := s.attempt(ctx, client, pageURL)
		if clearance != "" {
			return &Result{
				Clearance: clearance, Cookies: client.GetCookies(page),
				UserAgent: s.cfg.UserAgent, Client: client, Attempts: attempt,
			}, nil
		}
		if err != nil {
			lastErr = err
			if !retryable(err) {
				return nil, err
			}
		}
		if attempt < s.cfg.MaxAttempts && retryAfter > 0 {
			if err := sleep(ctx, retryAfter); err != nil {
				return nil, err
			}
		}
	}
	return nil, lastErr
}

// attempt runs one solve. It returns the clearance, or a wait before the next attempt and why it failed.
func (s *Solver) attempt(ctx context.Context, client tls_client.HttpClient, pageURL string) (string, time.Duration, error) {
	out, err := s.call(ctx, &stepAdvance{Start: &stepStart{
		URL: pageURL, UserAgent: s.cfg.UserAgent,
		FinishAtForm: true, ClientPacingV1: true, ClientJarWritesV1: true,
	}})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.retryAfter > 0 {
			return "", apiErr.retryAfter, err
		}
		return "", 0, err
	}
	for {
		switch out.Kind {
		case "request":
			resp := perform(ctx, client, out)
			if err := ctx.Err(); err != nil {
				s.abort(out)
				return "", 0, err
			}
			if out, err = s.call(ctx, &stepAdvance{Context: out.Context, Sequence: out.Sequence, Response: resp}); err != nil {
				return "", 0, err
			}
		case "final":
			resp := perform(ctx, client, out)
			if resp.Error != "" {
				return "", 0, fmt.Errorf("cloudflare: form POST: %s", resp.Error)
			}
			if hasHeader(resp.Headers, "cf-mitigated") {
				return "", 0, ErrNotCleared
			}
			return clearanceFrom(client, out.PayloadURL), 0, nil
		case "complete":
			if out.Result != nil && out.Result.Outcome == "cleared" {
				if out.Result.Clearance != "" {
					return out.Result.Clearance, 0, nil
				}
				return clearanceFrom(client, pageURL), 0, nil
			}
			return "", nextWait(out.Next), ErrNotCleared
		case "error", "aborted":
			se := &SolveError{Kind: out.Kind}
			if out.Failure != nil {
				se.Kind, se.Owner, se.RetrySafe = out.Failure.Kind, out.Failure.Owner, out.Failure.RetrySafe
			}
			if out.Next != nil {
				se.RetrySafe = true
			}
			return "", nextWait(out.Next), se
		default:
			return "", 0, fmt.Errorf("cloudflare: unexpected step kind %q", out.Kind)
		}
	}
}

func (s *Solver) call(ctx context.Context, in *stepAdvance) (*stepOutput, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost, s.cfg.Endpoint+"/v1/step", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", s.cfg.APIKey)
	req.Header.Set("User-Agent", apiUserAgent)
	resp, err := s.cfg.APIClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: api: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: api: %w", err)
	}
	if resp.StatusCode != nethttp.StatusOK {
		var e apiErrorBody
		_ = json.Unmarshal(raw, &e)
		apiErr := &APIError{Status: resp.StatusCode, Code: e.Code, Message: e.Error, RetrySafe: e.RetrySafe, RequestID: e.RequestID}
		if apiErr.Message == "" {
			apiErr.Message = strings.TrimSpace(string(raw))
		}
		if resp.StatusCode == nethttp.StatusTooManyRequests || apiErr.RetrySafe {
			apiErr.RetrySafe = true
			apiErr.retryAfter = time.Second
			if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
				apiErr.retryAfter = time.Duration(secs) * time.Second
			}
		}
		return nil, apiErr
	}
	var out stepOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("cloudflare: api: decode step: %w", err)
	}
	return &out, nil
}

// abort frees the context on the API after the caller gave up. Best effort.
func (s *Solver) abort(out *stepOutput) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.call(ctx, &stepAdvance{Context: out.Context, Sequence: out.Sequence, Abort: true})
}

func retryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.RetrySafe
	}
	var solveErr *SolveError
	if errors.As(err, &solveErr) {
		return solveErr.RetrySafe
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

func nextWait(next *stepNext) time.Duration {
	if next != nil && next.RetryAfterMs > 0 {
		return time.Duration(next.RetryAfterMs) * time.Millisecond
	}
	return 0
}

func clearanceFrom(client tls_client.HttpClient, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	for _, c := range client.GetCookies(u) {
		if c.Name == ClearanceCookie {
			return c.Value
		}
	}
	return ""
}

func hasHeader(headers []stepHeader, name string) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return true
		}
	}
	return false
}
