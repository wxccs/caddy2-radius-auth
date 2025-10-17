package caddy2_radius_auth

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	// Register the directive as a handler
	httpcaddyfile.RegisterHandlerDirective("radius_auth", parseCaddyfile)

	// For Caddy v2.10.2, we need to ensure the directive is recognized
	// as an ordered handler by properly implementing the necessary interfaces
	// Users will need to specify the order in their Caddyfile if needed:
	// order radius_auth before basic_auth
	httpcaddyfile.RegisterDirectiveOrder("radius_auth", httpcaddyfile.Before, "basic_auth")
}

// parseCaddyfile sets up the HTTPRadiusAuth middleware from Caddyfile configuration.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name

	var ra HTTPRadiusAuth

	for h.NextBlock(0) {
		switch h.Val() {

		case "servers":
			args := h.RemainingArgs()
			if len(args) == 0 {
				return nil, h.Err("servers requires at least one address")
			}

			for _, s := range args {
				if !strings.Contains(s, ":") {
					return nil, h.Errf("invalid RADIUS server address: %s (must include port)", s)
				}
				host, port, err := net.SplitHostPort(s)
				if err != nil || host == "" || port == "" {
					return nil, h.Errf("invalid RADIUS server format: %s", s)
				}
				ra.Servers = append(ra.Servers, s)
			}

		case "secret":
			if !h.NextArg() {
				return nil, h.Err("secret requires a value")
			}
			ra.Secret = h.Val()

		case "realm":
			if !h.NextArg() {
				return nil, h.Err("realm requires a value")
			}
			ra.Realm = h.Val()

		case "timeout":
			if !h.NextArg() {
				return nil, h.Err("timeout requires a duration value (e.g. 3s)")
			}
			_, err := time.ParseDuration(h.Val())
			if err != nil {
				return nil, h.Errf("invalid timeout duration: %v", err)
			}
			ra.Timeout = h.Val()

		case "cache_ttl":
			if !h.NextArg() {
				return nil, h.Err("cache_ttl requires a duration value (e.g. 300s)")
			}
			_, err := time.ParseDuration(h.Val())
			if err != nil {
				return nil, h.Errf("invalid cache_ttl duration: %v", err)
			}
			ra.CacheTTL = h.Val()

		default:
			return nil, h.Errf("unrecognized directive: %s", h.Val())
		}
	}

	if len(ra.Servers) == 0 {
		return nil, fmt.Errorf("at least one RADIUS server must be defined")
	}
	if ra.Secret == "" {
		return nil, fmt.Errorf("radius secret must be set")
	}
	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"radius_auth": caddyconfig.JSON(ra, nil),
		},
	}, nil
}
