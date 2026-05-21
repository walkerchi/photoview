package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/photoview/photoview/api/graphql/models"
	"github.com/photoview/photoview/api/log"
	"github.com/photoview/photoview/api/utils"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

// AuthTokenCookieName is the name of the cookie holding a Photoview access
// token (kept in sync with ui/src/helpers/authentication.ts).
const AuthTokenCookieName = "auth-token"

// HeaderAuthConfig is the parsed form of the PHOTOVIEW_HEADER_AUTH_* variables.
type HeaderAuthConfig struct {
	Enabled        bool
	UsernameHeader string
	TrustedProxies []*net.IPNet
}

var (
	headerAuthConfigOnce sync.Once
	headerAuthConfig     HeaderAuthConfig
)

// GetHeaderAuthConfig returns the parsed config, loading it from the
// environment on first use.
func GetHeaderAuthConfig() HeaderAuthConfig {
	headerAuthConfigOnce.Do(func() {
		headerAuthConfig = loadHeaderAuthConfig()
	})
	return headerAuthConfig
}

// ResetHeaderAuthConfigForTest forces the next GetHeaderAuthConfig call to
// re-read the environment. Tests use this; production code should not.
func ResetHeaderAuthConfigForTest() {
	headerAuthConfigOnce = sync.Once{}
}

func loadHeaderAuthConfig() HeaderAuthConfig {
	cfg := HeaderAuthConfig{
		Enabled:        utils.EnvHeaderAuthEnabled.GetBool(),
		UsernameHeader: utils.EnvHeaderAuthUsernameHeader.GetValue(),
	}
	if cfg.UsernameHeader == "" {
		cfg.UsernameHeader = "Remote-User"
	}
	raw := utils.EnvHeaderAuthTrustedProxies.GetValue()
	if raw == "" {
		// Default: loopback only — the safe choice when a reverse proxy on
		// the same host is the only thing allowed to inject identity.
		raw = "127.0.0.1/32,::1/128"
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			if strings.Contains(item, ":") {
				item += "/128"
			} else {
				item += "/32"
			}
		}
		_, cidr, err := net.ParseCIDR(item)
		if err != nil {
			log.Warn(nil, "Invalid CIDR in PHOTOVIEW_HEADER_AUTH_TRUSTED_PROXIES",
				"value", item, "error", err)
			continue
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, cidr)
	}
	if cfg.Enabled && len(cfg.TrustedProxies) == 0 {
		log.Warn(nil, "PHOTOVIEW_HEADER_AUTH_ENABLED=1 but no trusted proxies parsed; header auth will reject all requests")
	}
	return cfg
}

// IsTrustedRemote reports whether the connection's peer address falls inside
// one of the trusted proxy CIDRs.
func (c HeaderAuthConfig) IsTrustedRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range c.TrustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// applyHeaderAuth tries to authenticate the request via a Remote-User header
// injected by a trusted reverse proxy (e.g. Authelia, authentik, oauth2-proxy).
//
// On success it writes an auth-token Set-Cookie to w so the UI sees a logged-in
// session, and returns the matching user. On no-match it returns (nil, nil)
// — the caller should fall through to cookie-based auth.
func applyHeaderAuth(db *gorm.DB, w http.ResponseWriter, r *http.Request) (*models.User, error) {
	cfg := GetHeaderAuthConfig()
	if !cfg.Enabled {
		return nil, nil
	}
	if !cfg.IsTrustedRemote(r.RemoteAddr) {
		return nil, nil
	}
	username := strings.TrimSpace(r.Header.Get(cfg.UsernameHeader))
	if username == "" {
		return nil, nil
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.Wrap(err, "header auth: lookup user")
		}
		provisioned, err := models.RegisterUser(db, username, nil, false)
		if err != nil {
			return nil, errors.Wrap(err, "header auth: auto-provision user")
		}
		user = *provisioned
		log.Info(r.Context(), "header auth: provisioned new user", "username", username)
	}

	// Reuse the longest-lived non-expired token, otherwise mint a fresh one.
	// This keeps the access_tokens table bounded under steady-state SSO use.
	var token models.AccessToken
	err := db.Where("user_id = ? AND expire > ?", user.ID, time.Now()).
		Order("expire DESC").First(&token).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.Wrap(err, "header auth: lookup access token")
		}
		fresh, err := user.GenerateAccessToken(db)
		if err != nil {
			return nil, errors.Wrap(err, "header auth: mint access token")
		}
		token = *fresh
	}

	http.SetCookie(w, &http.Cookie{
		Name:     AuthTokenCookieName,
		Value:    token.Value,
		Path:     "/",
		Expires:  token.Expire,
		SameSite: http.SameSiteLaxMode,
	})
	return &user, nil
}
