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
	"time"
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
	host       string
	repoPrefix string
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[INIT] Starting container registry reverse proxy")

	host := os.Getenv("HOST")
	log.Printf("[ENV] HOST=%s", host)

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("[ERROR] PORT environment variable not specified")
	}
	log.Printf("[ENV] PORT=%s", port)

	browserRedirects := os.Getenv("DISABLE_BROWSER_REDIRECTS") == ""
	log.Printf("[CONFIG] Browser redirects enabled: %v", browserRedirects)

	registryHost := os.Getenv("REGISTRY_HOST")
	if registryHost == "" {
		log.Fatal("[ERROR] REGISTRY_HOST environment variable not specified (example: gcr.io)")
	}
	log.Printf("[ENV] REGISTRY_HOST=%s", registryHost)

	repoPrefix := os.Getenv("REPO_PREFIX")
	if repoPrefix == "" {
		log.Fatal("[ERROR] REPO_PREFIX environment variable not specified")
	}
	log.Printf("[ENV] REPO_PREFIX=%s", repoPrefix)

	reg := registryConfig{host: registryHost, repoPrefix: repoPrefix}

	tokenEndpoint, err := discoverTokenService(reg.host)
	if err != nil {
		log.Fatalf("[ERROR] Token endpoint discovery failed: %+v", err)
	}
	log.Printf("[DISCOVERY] Token endpoint: %s", tokenEndpoint)

	var auth authenticator
	if basic := os.Getenv("AUTH_HEADER"); basic != "" {
		log.Println("[AUTH] Using AUTH_HEADER for basic auth")
		auth = authHeader(basic)
	} else if gcpKey := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); gcpKey != "" {
		b, err := ioutil.ReadFile(gcpKey)
		if err != nil {
			log.Fatalf("[ERROR] Could not read GCP key file from %s: %+v", gcpKey, err)
		}
		log.Printf("[AUTH] Using service account json from %s", gcpKey)
		auth = authHeader("Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("_json_key:%s", string(b)))))
	} else {
		log.Println("[AUTH] No authentication provided. Requests will be unauthenticated.")
	}

	mux := http.NewServeMux()
	if browserRedirects {
		mux.Handle("/", browserRedirectHandler(reg))
	}
	if tokenEndpoint != "" {
		mux.Handle("/_token", tokenProxyHandler(tokenEndpoint, repoPrefix))
	}
	mux.Handle("/v2/", registryAPIProxy(reg, auth))

	addr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("[SERVER] Listening on %s", addr)
	handler := captureHostHeader(mux)
	if cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"); cert != "" && key != "" {
		err = http.ListenAndServeTLS(addr, cert, key, handler)
	} else {
		err = http.ListenAndServe(addr, handler)
	}
	if err != http.ErrServerClosed {
		log.Fatalf("[FATAL] Server listen error: %+v", err)
	}
	log.Println("[SERVER] Shutdown completed")
}

func discoverTokenService(registryHost string) (string, error) {
	url := fmt.Sprintf("https://%s/v2/", registryHost)
	log.Printf("[DISCOVERY] Requesting token service from %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed GET to %s: %+v", url, err)
	}
	defer resp.Body.Close()
	log.Printf("[DISCOVERY] Response status: %s", resp.Status)

	hdr := resp.Header.Get("www-authenticate")
	log.Printf("[DISCOVERY] Www-Authenticate header: %s", hdr)
	if hdr == "" {
		return "", fmt.Errorf("www-authenticate header missing from %s response", url)
	}
	matches := realm.FindStringSubmatch(hdr)
	if len(matches) == 0 {
		return "", fmt.Errorf("realm not found in Www-Authenticate header: %s", hdr)
	}
	return matches[1], nil
}

func captureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		log.Printf("[REQUEST] Captured host header: %s", req.Host)
		req = req.WithContext(ctx)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

func tokenProxyHandler(tokenEndpoint, repoPrefix string) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director: func(r *http.Request) {
			orig := r.URL.String()
			q := r.URL.Query()
			scope := q.Get("scope")
			if scope == "" {
				log.Printf("[TOKEN] No scope found in request: %s", orig)
				return
			}
			newScope := strings.Replace(scope, "repository:", fmt.Sprintf("repository:%s/", repoPrefix), 1)
			q.Set("scope", newScope)
			u, _ := url.Parse(tokenEndpoint)
			u.RawQuery = q.Encode()
			r.URL = u
			r.Host = u.Host
			log.Printf("[TOKEN] Rewrote URL: %s => %s", orig, r.URL.String())
		},
	}).ServeHTTP
}

func browserRedirectHandler(cfg registryConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURL := fmt.Sprintf("https://%s/%s%s", cfg.host, cfg.repoPrefix, r.RequestURI)
		log.Printf("[REDIRECT] Browser request %s => %s", r.RequestURI, redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
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
		u := req.URL.String()
		req.Host = c.host
		req.URL.Scheme = "https"
		req.URL.Host = c.host
		if req.URL.Path != "/v2/" {
			req.URL.Path = re.ReplaceAllString(req.URL.Path, fmt.Sprintf("/v2/%s/", c.repoPrefix))
		}
		log.Printf("[REWRITE] URL: %s => %s", u, req.URL.String())
	}
}

type registryRoundtripper struct {
	auth authenticator
}

func (rrt *registryRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("[ROUNDTRIP] Request: %s %s", req.Method, req.URL.String())

	if rrt.auth != nil {
		header := rrt.auth.AuthHeader()
		log.Printf("[AUTH] Setting Authorization header: %s", header[:16]+"...")
		req.Header.Set("Authorization", header)
	}

	if origHost, ok := req.Context().Value(ctxKeyOriginalHost).(string); ok {
		ua := req.Header.Get("user-agent")
		if ua != "" {
			req.Header.Set("user-agent", "gcr-proxy/0.1 customDomain/"+origHost+" "+ua)
		}
	}

	start := time.Now()
	resp, err := http.DefaultTransport.RoundTrip(req)
	log.Printf("[ROUNDTRIP] Duration: %s", time.Since(start))
	if err != nil {
		log.Printf("[ERROR] Request failed: %+v", err)
		return nil, err
	}

	log.Printf("[ROUNDTRIP] Response: %d %s", resp.StatusCode, resp.Status)

	if locHdr := resp.Header.Get("location"); req.Method == http.MethodGet &&
		resp.StatusCode == http.StatusFound && strings.HasPrefix(locHdr, "/") {
		newLoc := req.URL.Scheme + "://" + req.URL.Host + locHdr
		resp.Header.Set("location", newLoc)
		log.Printf("[REDIRECT] Rewrote redirect location: %s", newLoc)
	}

	updateTokenEndpoint(resp, req.Host)
	return resp, nil
}

func updateTokenEndpoint(resp *http.Response, host string) {
	v := resp.Header.Get("www-authenticate")
	if v != "" {
		newVal := realm.ReplaceAllString(v, fmt.Sprintf(`realm="https://%s/_token"`, host))
		resp.Header.Set("www-authenticate", newVal)
		log.Printf("[TOKEN] Updated Www-Authenticate header: %s", newVal)
	}
}

type authenticator interface {
	AuthHeader() string
}

type authHeader string

func (b authHeader) AuthHeader() string { return string(b) }
