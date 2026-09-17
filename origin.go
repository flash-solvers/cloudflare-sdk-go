package cloudflare

import (
	"context"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
)

const maxOriginBody = 16 << 20

// perform makes one origin request exactly as the API described it and measures it.
func perform(ctx context.Context, client tls_client.HttpClient, step *stepOutput) *stepResponse {
	var pacing time.Duration
	if step.PacingMs > 0 {
		started := time.Now()
		if err := sleep(ctx, time.Duration(step.PacingMs)*time.Millisecond); err != nil {
			return &stepResponse{Error: err.Error(), Timing: &stepTiming{PacingUs: time.Since(started).Microseconds()}}
		}
		pacing = time.Since(started)
	}
	target, err := url.Parse(step.PayloadURL)
	if err != nil {
		return &stepResponse{Error: err.Error(), Timing: &stepTiming{PacingUs: pacing.Microseconds()}}
	}
	if len(step.SetCookies) > 0 {
		client.SetCookies(target, jarCookies(step.SetCookies))
	}
	if step.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(step.TimeoutMs)*time.Millisecond)
		defer cancel()
	}
	var body io.Reader
	if step.Payload != "" {
		body = strings.NewReader(step.Payload)
	}
	req, err := http.NewRequestWithContext(ctx, step.Method, step.PayloadURL, body)
	if err != nil {
		return &stepResponse{Error: err.Error(), Timing: &stepTiming{PacingUs: pacing.Microseconds()}}
	}
	for _, h := range step.Headers {
		req.Header.Add(h.Name, h.Value)
	}
	req.Header[http.HeaderOrderKey] = step.HeaderOrder
	if step.Host != "" {
		req.Host = step.Host
	}

	started := time.Now()
	var gotConn, firstByte time.Time
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { gotConn = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}))
	failed := func(err error) *stepResponse {
		return &stepResponse{Error: err.Error(), Timing: &stepTiming{
			DurationMs: time.Since(started).Milliseconds(), PacingUs: pacing.Microseconds()}}
	}
	resp, err := client.Do(req)
	if err != nil {
		return failed(err)
	}
	defer resp.Body.Close()
	decoded := resp.Body
	if !resp.Uncompressed {
		decoded = http.DecompressBodyByType(resp.Body, resp.Header.Get("Content-Encoding"))
	}
	raw, err := io.ReadAll(io.LimitReader(decoded, maxOriginBody))
	if err != nil {
		return failed(err)
	}
	ended := time.Now()

	out := &stepResponse{Status: resp.StatusCode}
	if utf8.Valid(raw) {
		out.Data = string(raw)
	} else {
		out.DataBin = raw
	}
	for name, values := range resp.Header {
		for _, v := range values {
			out.Headers = append(out.Headers, stepHeader{Name: name, Value: v})
		}
	}
	since := func(at time.Time) int64 {
		if at.IsZero() || at.Before(started) {
			return 0
		}
		return at.Sub(started).Milliseconds()
	}
	out.Timing = &stepTiming{
		RequestStartMs: since(gotConn), ResponseStartMs: since(firstByte),
		DurationMs: ended.Sub(started).Milliseconds(), PacingUs: pacing.Microseconds(),
	}
	if n, err := strconv.Atoi(resp.Header.Get("Content-Length")); err == nil && n >= 0 {
		out.Timing.WireBytes = &n
	}
	return out
}

func jarCookies(in []stepCookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(in))
	for _, c := range in {
		cookie := &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Secure: c.Secure}
		if c.ExpiresUnix > 0 {
			cookie.Expires = time.Unix(c.ExpiresUnix, 0)
		}
		switch strings.ToLower(c.SameSite) {
		case "lax":
			cookie.SameSite = http.SameSiteLaxMode
		case "strict":
			cookie.SameSite = http.SameSiteStrictMode
		case "none":
			cookie.SameSite = http.SameSiteNoneMode
		}
		out = append(out, cookie)
	}
	return out
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
