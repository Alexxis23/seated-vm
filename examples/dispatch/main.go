// Command dispatch is a complete, runnable skeleton of the SDK's dispatch
// flow using the real core wasm:
//
//	go run ./examples/dispatch -key prld_live_... -env ../env_sig86.json
//
// It loads browser params from the env JSON, prepares the exact request the
// SDK sends (payload body + every header), and POSTs it. With -dry-run it
// prints the request instead of sending.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	seatedvm "github.com/Alexxis23/seated-vm"
)

func main() {
	key := flag.String("key", "", "X-SDK-Key (required to actually send)")
	envPath := flag.String("env", "env_sig86.json", "browser params JSON")
	dry := flag.Bool("dry-run", false, "print the request instead of sending")
	flag.Parse()

	raw, err := os.ReadFile(*envPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var j map[string]any
	if err := json.Unmarshal(raw, &j); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	p := seatedvm.ParamsFromJSON(j)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	core, err := seatedvm.NewCore(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "core:", err)
		os.Exit(1)
	}
	defer core.Close(ctx)

	dr, err := core.PrepareDispatch(ctx, p, *key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prepare:", err)
		os.Exit(1)
	}
	fmt.Printf("endpoint   : %s\n", dr.Endpoint)
	fmt.Printf("dispatchID : %s\n", dr.DispatchID)
	fmt.Printf("userAgent  : %s\n", dr.SDKUserAgent)
	fmt.Printf("body       : %d bytes (raw-deflate)\n", len(dr.Body))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dr.Endpoint, bytes.NewReader(dr.Body))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dr.SetHeaders(req)

	if *dry {
		fmt.Println("--- request (dry run) ---")
		fmt.Println(req.Method, req.URL)
		for k, v := range req.Header {
			fmt.Printf("%s: %s\n", k, v)
		}
		return
	}
	if *key == "" {
		fmt.Fprintln(os.Stderr, "-key is required without -dry-run")
		os.Exit(2)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "post:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("response   : %s %s\n", resp.Proto, resp.Status)
	if len(body) > 0 {
		fmt.Printf("body       : %s\n", body)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		os.Exit(1)
	}
	fmt.Println("dispatched :", dr.DispatchID)
}
