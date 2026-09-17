# Flash Solvers Cloudflare SDK for Go

Solve the Cloudflare WAF challenge ("Just a moment...") with the [Flash Solvers](https://flashsolvers.com/) API and get a `cf_clearance` cookie.

The API only generates each step of the challenge.
Every request to the protected site is made from your machine, with a Chrome 152 TLS fingerprint, your proxy and your cookie jar.

## Install

```sh
go get github.com/flash-solvers/cloudflare-sdk-go
```

Requires Go 1.24 or newer.

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	cloudflare "github.com/flash-solvers/cloudflare-sdk-go"
)

func main() {
	solver, err := cloudflare.New(cloudflare.Config{
		APIKey: "your-api-key",
		Proxy:  "http://user:pass@host:port",
	})
	if err != nil {
		log.Fatal(err)
	}

	res, err := solver.Solve(context.Background(), "https://shop.axs.com/")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("cf_clearance:", res.Clearance)
	fmt.Println("user agent:", res.UserAgent)
}
```

Use the cookie with the same proxy IP and `res.UserAgent`, or Cloudflare will challenge you again.
`res.Client` is the session that solved the challenge, with the cookie already in its jar, so you can keep making requests with it.

## Config

| Field | Default | Description |
|---|---|---|
| `APIKey` | required | Your Flash Solvers API key |
| `Proxy` | none | `http://`, `https://` or `socks5://` proxy for every request to the site |
| `MaxAttempts` | `3` | Solves to start before giving up |
| `Client` | new per attempt | Your own `tls_client.HttpClient`. It must not follow redirects. Build one with `cloudflare.NewClient(proxy)` |
| `UserAgent` | Chrome 152 on macOS | Must match the API's browser profile. Leave it unset |
| `Endpoint` | `https://cf.flashsolvers.com` | API base URL |
| `APIClient` | 60 second timeout | `*http.Client` for API calls |

## Result

| Field | Description |
|---|---|
| `Clearance` | The `cf_clearance` cookie value |
| `Cookies` | All cookies for the solved URL |
| `UserAgent` | User agent to send with the cookies |
| `Client` | The session that solved the challenge |
| `Attempts` | How many solves were started |

## Errors

| Error | Cause | Retried |
|---|---|---|
| `*cloudflare.APIError` with `Code` `host_not_allowed` | The site is not supported | No |
| `*cloudflare.APIError` with `Code` `invalid_key`, `key_expired`, `insufficient_balance` | Key or balance problem | No |
| `*cloudflare.APIError` with `Code` `at_capacity` | Too many solves in flight | Yes, after `Retry-After` |
| `*cloudflare.SolveError` | The solve failed. `Kind` says why, such as `origin_refused` | When `RetrySafe` |
| `cloudflare.ErrNotCleared` | Cloudflare did not accept any attempt | Each attempt is retried until `MaxAttempts` |

Each retry uses a fresh session, because Cloudflare keeps rejecting a session that failed once.
A proxy IP that keeps failing is usually flagged; rotate it.

## Supported sites and pricing

See the [Flash Solvers docs](https://flashsolvers.com/).
You are charged once per solve that reaches the final form, never for failures.
