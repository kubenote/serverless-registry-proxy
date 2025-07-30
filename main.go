package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
)

type myContextKey string

const (
	ctxKeyOriginalHost = myContextKey("original-host")
)

func main() {
	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf("%s:%s", host, port)

	mux := http.NewServeMux()
	mux.Handle("/v2/", registryAPIProxy())

	handler := captureHostHeader(mux)
	log.Printf("[proxy] starting to listen on %s", addr)
	err := http.ListenAndServe(addr, handler)
	if err != http.ErrServerClosed {
		log.Fatalf("listen error: %+v", err)
	}
}

func captureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		req = req.WithContext(ctx)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

func registryAPIProxy() http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director: func(req *http.Request) {
			original := req.URL.String()

			// Hardcode redirect to GHCR image manifest
			req.Host = "ghcr.io"
			req.URL.Scheme = "https"
			req.URL.Host = "ghcr.io"
			req.URL.Path = "/v2/kubenote/kubeforge/manifests/latest"

			log.Printf("[proxy] fully hardcoded url: %s -> %s", original, req.URL)
		},
		Transport: &registryRoundtripper{},
	}).ServeHTTP
}

type registryRoundtripper struct{}

func (rrt *registryRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("[transport] REQUEST: %s %s", req.Method, req.URL)

	origHost := req.Context().Value(ctxKeyOriginalHost).(string)
	if ua := req.Header.Get("User-Agent"); ua != "" {
		req.Header.Set("User-Agent", "ghcr-proxy/1.0 customDomain/"+origHost+" "+ua)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Printf("[transport] error: %+v", err)
		return nil, err
	}

	log.Printf("[transport] RESPONSE: %d %s", resp.StatusCode, resp.Status)

	// Handle redirect paths for blob downloads
	if loc := resp.Header.Get("Location"); req.Method == http.MethodGet && resp.StatusCode == http.StatusFound && strings.HasPrefix(loc, "/") {
		resp.Header.Set("Location", req.URL.Scheme+"://"+req.URL.Host+loc)
	}

	return resp, nil
}
