package cloudflare

import (
	"errors"
	"fmt"
	"time"
)

// ErrNotCleared means every attempt finished without a cf_clearance cookie.
var ErrNotCleared = errors.New("cloudflare: challenge not cleared")

// APIError is a request the Flash Solvers API rejected, such as a bad key or an unsupported host.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RetrySafe bool
	RequestID string

	retryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cloudflare: api %d %s: %s (request %s)", e.Status, e.Code, e.Message, e.RequestID)
}

// SolveError is a solve the API ended with kind "error" or "aborted".
type SolveError struct {
	Kind      string
	Owner     string
	RetrySafe bool
}

func (e *SolveError) Error() string {
	return fmt.Sprintf("cloudflare: solve failed: %s (owner %s, retrySafe %t)", e.Kind, e.Owner, e.RetrySafe)
}
