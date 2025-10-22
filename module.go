package caddy2_radius_auth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(HTTPRadiusAuth{})
}

type HTTPRadiusAuth struct {
	Servers  []string     `json:"servers,omitempty"`   // List of RADIUS servers
	Secret   string       `json:"secret,omitempty"`    // Shared secret
	Realm    string       `json:"realm,omitempty"`     // Basic Auth realm
	Timeout  string       `json:"timeout,omitempty"`   // Connection timeout (default "3s")
	CacheTTL string       `json:"cache_ttl,omitempty"` // Cache TTL (0 to disable, default "0s")
	cache    *cache.Cache // Internal cache instance
	logger   *zap.Logger
}

func (HTTPRadiusAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.radius_auth",
		New: func() caddy.Module { return new(HTTPRadiusAuth) },
	}
}

// Provision validates configuration and initializes middleware
func (r *HTTPRadiusAuth) Provision(ctx caddy.Context) error {
	r.logger = ctx.Logger()
	if len(r.Servers) == 0 {
		return fmt.Errorf("no RADIUS servers configured")
	}
	if r.Secret == "" {
		return fmt.Errorf("missing RADIUS shared secret")
	}
	if r.Timeout == "" {
		r.Timeout = "3s"
	}
	if r.CacheTTL == "" {
		r.CacheTTL = "0s"
	}

	// Initialize cache
	cacheTTL, err := time.ParseDuration(r.CacheTTL)
	if err != nil {
		return fmt.Errorf("invalid cache_ttl duration: %v", err)
	}
	// Use a reasonable default capacity of 1000 items
	if cacheTTL > 0 {
		r.cache = cache.New(cacheTTL, time.Second)
	} else {
		r.cache = nil
	}

	// Validate server addresses
	valid := make([]string, 0, len(r.Servers))
	for _, s := range r.Servers {
		if isValidServerAddr(s) {
			valid = append(valid, s)
		} else {
			fmt.Printf("[caddy-radius] skipped invalid RADIUS server: %s\n", s)
		}
	}
	r.Servers = valid
	if len(r.Servers) == 0 {
		return fmt.Errorf("no valid RADIUS servers remain after validation")
	}

	return nil
}

// isValidServerAddr validates a host:port format
func isValidServerAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return false
	}
	if net.ParseIP(host) == nil && strings.Contains(host, " ") {
		return false
	}
	return true
}

// Authenticate ServeHTTP handles HTTP requests and performs RADIUS authentication
func (r HTTPRadiusAuth) Authenticate(w http.ResponseWriter, req *http.Request) (caddyauth.User, bool, error) {
	user, pass, ok := req.BasicAuth()
	if !ok {
		return r.promptForCredentials(w, nil)
	}

	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", user, pass)
	if r.cache != nil {
		if cachedResult, found := r.cache.Get(cacheKey); found {
			if cachedResult.(bool) {
				return caddyauth.User{ID: user}, true, nil
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return r.promptForCredentials(w, nil)
			}
		}
	}

	// Perform RADIUS authentication
	ok, err := r.checkRadiusConcurrent(user, pass)
	if err != nil {
		http.Error(w, fmt.Sprintf("RADIUS error: %v", err), http.StatusInternalServerError)
		return r.promptForCredentials(w, nil)
	}

	// Cache the result
	if r.cache != nil {
		r.cache.SetDefault(cacheKey, ok)
	}

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return r.promptForCredentials(w, nil)
	}

	return caddyauth.User{ID: user}, true, nil
}

func (r HTTPRadiusAuth) promptForCredentials(w http.ResponseWriter, err error) (caddyauth.User, bool, error) {
	// browsers show a message that says something like:
	// "The website says: <realm>"
	// which is kinda dumb, but whatever.
	realm := r.Realm
	if realm == "" {
		realm = "restricted"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	return caddyauth.User{}, false, err
}

// Interface guards
var (
	_ caddy.Provisioner       = (*HTTPRadiusAuth)(nil)
	_ caddyauth.Authenticator = (*HTTPRadiusAuth)(nil)
)
