// Solve a Cloudflare challenge and print the cf_clearance cookie.
//
//	FLASH_API_KEY=... go run ./examples/solve https://shop.axs.com/
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	cloudflare "github.com/flash-solvers/cloudflare-sdk-go"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: solve <url>")
	}
	solver, err := cloudflare.New(cloudflare.Config{
		APIKey:   os.Getenv("FLASH_API_KEY"),
		Proxy:    os.Getenv("PROXY"),
		Endpoint: os.Getenv("FLASH_ENDPOINT"),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := solver.Solve(ctx, os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("cf_clearance=%s\nattempts=%d\n", res.Clearance, res.Attempts)
}
