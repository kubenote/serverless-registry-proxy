/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
)

const (
	ctxKeyOriginalHost = myContextKey("original-host")
)

var (
	realm              = regexp.MustCompile(`realm="(.*?)"`)
)

type myContextKey string

type registryConfig struct {
	host       string
}

func main() {
	host := os.Getenv("HOST")

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable not specified")
	}
	browserRedirects := os.Getenv("DISABLE_BROWSER_REDIRECTS") == ""

	registryHost := os.Getenv("REGISTRY_HOST")
	if registryHost == "" {
		log.Fatal("REGISTRY_HOST environment variable not specified (example: gcr.io)")
	}


	reg := registryConfig{
		host:       registryHost,
	}

	tokenEndpoint, err := discoverTokenService(reg.host)
	if err != nil {
		log.Fatalf("target registry's token endpoint could not be discovered: %+v", err)
	}
	log.Printf("discovered token endpoint for backend registry: %s", tokenEndpoint)

	var auth authenticator
	if basic := os.Getenv("AUTH_HEADER"); basic != "" {
		auth = authHeader(basic)
	} else if gcpKey := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); gcpKey != "" {
		b, err := ioutil.ReadFile(gcpKey)
		if err != nil {
			log.Fatalf("could not read key file from %s: %+v", gcpKey, err)
		}
		log.Printf("using specified service account json key to authenticate proxied requests")
		auth = authHeader("Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("_json_key:%s", string(b)))))
	}

	mux := http.NewServeMux()
	if browserRedirects {
		mux.Handle("/", browserRedirectHandler())
	}
	mux.Handle("/v2/", registryAPIProxy(reg, auth))

	addr := fmt.Sprintf("%s:%s", host, port)
	handler := captureHostHeader(mux)
	log.Printf("starting to listen on %s", addr)
	if cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"); cert != "" && key != "" {
		err = http.ListenAndServeTLS(addr, cert, key, handler)
	} else {
		err = http.ListenAndServe(addr, handler)
	}
	if err != http.ErrServerClosed {
		log.Fatalf("listen error: %+v", err)
	}

	log.Printf("server shutdown successfully")
}

func discoverTokenService(registryHost string) (string, error) {
	url := fmt.Sprintf("https://%s/v2/", registryHost)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query the registry host %s: %+v", registryHost, err)
	}
	hdr := resp.Header.Get("www-authenticate")
	if hdr == "" {
		return "", fmt.Errorf("www-authenticate header not returned from %s, cannot locate token endpoint", url)
	}
	matches := realm.FindStringSubmatch(hdr)
	if len(matches) == 0 {
		return "", fmt.Errorf("cannot locate 'realm' in %s response header www-authenticate: %s", url, hdr)
	}
	return matches[1], nil
}

// captureHostHeader is a middleware to capture Host header in a context key.
func captureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		req = req.WithContext(ctx)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}


// browserRedirectHandler redirects a request like example.com/my-image to
// REGISTRY_HOST/my-image, which shows a public UI for browsing the registry.
// This works only on registries that support a web UI when the image name is
// entered into the browser, like GCR (gcr.io/google-containers/busybox).
func browserRedirectHandler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Redirect all browser hits to the GitHub container package UI (optional)
        http.Redirect(w, r, "https://github.com/kubenote/KubeForge/pkgs/container/kubeforge", http.StatusTemporaryRedirect)
    }
}


// registryAPIProxy returns a reverse proxy to the specified registry.
func registryAPIProxy(cfg registryConfig, auth authenticator) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rewriteRegistryV2URL(cfg),
		Transport: &registryRoundtripper{
			auth: authHeader(""), // no hardcoded auth
		},
	}).ServeHTTP
}

// rewriteRegistryV2URL rewrites request.URL like /v2/* that come into the server
// into https://[GCR_HOST]/v2/[PROJECT_ID]/*. It leaves /v2/ as is.
func rewriteRegistryV2URL(_ registryConfig) func(*http.Request) {
    return func(req *http.Request) {
        original := req.URL.String()

        req.Host = "ghcr.io"
        req.URL.Scheme = "https"
        req.URL.Host = "ghcr.io"

        if strings.Contains(req.URL.Path, "/manifests/") {
            // Always redirect manifest pulls to latest
            req.URL.Path = "/v2/kubenote/kubeforge/manifests/latest"
        } else if strings.Contains(req.URL.Path, "/blobs/") {
            // Preserve blob digest
            parts := strings.Split(req.URL.Path, "/blobs/")
            if len(parts) == 2 {
                req.URL.Path = "/v2/kubenote/kubeforge/blobs/" + parts[1]
            } else {
                req.URL.Path = "/v2/kubenote/kubeforge/blobs/"
            }
        } else {
            req.URL.Path = "/v2/kubenote/kubeforge/"
        }

        log.Printf("[proxy] fully hardcoded url: %s → %s", original, req.URL)
    }
}



type registryRoundtripper struct {
	auth authenticator
}

func (rrt *registryRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Do not inject Authorization if the client already set one
	if req.Header.Get("Authorization") == "" && rrt.auth != nil {
		req.Header.Set("Authorization", rrt.auth.AuthHeader())
	}

	// Forward the request
	return http.DefaultTransport.RoundTrip(req)
}




type authenticator interface {
	AuthHeader() string
}

type authHeader string

func (b authHeader) AuthHeader() string { return string(b) }
