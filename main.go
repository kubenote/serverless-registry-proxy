package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const (
	ctxKeyOriginalHost = myContextKey("original-host")
)

var (
	re    = regexp.MustCompile(`^/v2/`)
	realm = regexp.MustCompile(`realm="(.*?)"`)
)

type myContextKey string

type registryConfig struct {
	host string
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
		host: registryHost,
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
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(segments) == 1 && segments[0] != "" {
				tag := segments[0]
				// Construct a Docker registry API call for the hardcoded image with the given tag
				http.Redirect(w, r, fmt.Sprintf("/v2/kubenote/kubeforge/manifests/%s", tag), http.StatusTemporaryRedirect)
				return
			}
			browserRedirectHandler(reg)(w, r)
		})
	}
	if tokenEndpoint != "" {
		mux.Handle("/_token", tokenProxyHandler(tokenEndpoint))
	}
	mux.Handle("/v2/", registryAPIProxy(reg, auth))

	addr := fmt.Sprintf("%s:%s", host, port)
	handler := loggingMiddleware(captureHostHeader(mux))
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

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[INCOMING] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
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

func captureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		req = req.WithContext(ctx)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

func tokenProxyHandler(tokenEndpoint string) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director: func(r *http.Request) {
			orig := r.URL.String()

			q := r.URL.Query()
			scope := q.Get("scope")
			if scope == "" {
				log.Printf("tokenProxyHandler: missing scope in original URL: %s", orig)
				return
			}

			// Fully override the scope
			newScope := "repository:kubenote/kubeforge:pull"
			q.Set("scope", newScope)

			u, err := url.Parse(tokenEndpoint)
			if err != nil {
				log.Printf("tokenProxyHandler: failed to parse tokenEndpoint '%s': %v", tokenEndpoint, err)
				return
			}
			u.RawQuery = q.Encode()
			r.URL = u
			r.Host = u.Host

			log.Printf("tokenProxyHandler: rewrote url: %s into: %s", orig, r.URL.String())
		},
	}).ServeHTTP
}

func browserRedirectHandler(cfg registryConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("https://%s/kubenote/kubeforge%s", cfg.host, r.RequestURI)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func registryAPIProxy(cfg registryConfig, auth authenticator) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rewriteRegistryV2URL(cfg),
		Transport: &registryRoundtripper{
			auth: auth,
		},
	}).ServeHTTP
}

func rewriteRegistryV2URL(c registryConfig) func(*http.Request) {
	return func(req *http.Request) {
		orig := req.URL.String()
		req.Host = c.host
		req.URL.Scheme = "https"
		req.URL.Host = c.host

		if req.URL.Path == "/v2/" {
			log.Printf("passing through /v2/ ping without rewriting")
			return
		}

		// Match: /v2/<repo>/manifests/<tag>
		parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/v2/"), "/")
		if len(parts) >= 3 && parts[1] == "manifests" {
			identifier := parts[2] // could be a tag or digest
		
			if strings.HasPrefix(identifier, "sha256:") {
				log.Printf("📦 pulling by digest: %s", identifier)
				req.URL.Path = fmt.Sprintf("/v2/kubenote/kubeforge/manifests/%s", identifier)
			} else {
				log.Printf("⚓ pulling tag: %s", identifier)
				req.URL.Path = fmt.Sprintf("/v2/kubenote/kubeforge/manifests/%s", identifier)
			}
		} else if len(parts) >= 2 && parts[0] != "" {
			// fallback for blobs/layers
			req.URL.Path = fmt.Sprintf("/v2/kubenote/kubeforge/%s/%s", parts[1], parts[2])
		} else {
			req.URL.Path = "/v2/kubenote/kubeforge"
		}

		log.Printf("rewrote url: %s into %s", orig, req.URL)
	}
}



type registryRoundtripper struct {
	auth authenticator
}

func (rrt *registryRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("request received. url=%s", req.URL)

	if rrt.auth != nil {
		req.Header.Set("Authorization", rrt.auth.AuthHeader())
	}

	origHost := req.Context().Value(ctxKeyOriginalHost).(string)
	if ua := req.Header.Get("user-agent"); ua != "" {
		req.Header.Set("user-agent", "gcr-proxy/0.1 customDomain/"+origHost+" "+ua)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		log.Printf("request completed (status=%d) url=%s", resp.StatusCode, req.URL)
	} else {
		log.Printf("request failed with error: %+v", err)
		return nil, err
	}

	if locHdr := resp.Header.Get("location"); req.Method == http.MethodGet &&
		resp.StatusCode == http.StatusFound && strings.HasPrefix(locHdr, "/") {
		resp.Header.Set("location", req.URL.Scheme+":"+"//"+req.URL.Host+locHdr)
	}

	updateTokenEndpoint(resp, origHost)
	return resp, nil
}

func updateTokenEndpoint(resp *http.Response, host string) {
	v := resp.Header.Get("www-authenticate")
	if v == "" {
		return
	}
	cur := fmt.Sprintf("https://%s/_token", host)
	resp.Header.Set("www-authenticate", realm.ReplaceAllString(v, fmt.Sprintf(`realm="%s"`, cur)))
}

type authenticator interface {
	AuthHeader() string
}

type authHeader string

func (b authHeader) AuthHeader() string { return string(b) }
