package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/photoview/photoview/api/dataloader"
	"github.com/photoview/photoview/api/graphql/auth"
	"github.com/photoview/photoview/api/graphql/models"
	"github.com/photoview/photoview/api/test_utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestHeaderAuthConfig_TrustedProxies(t *testing.T) {
	cases := []struct {
		name           string
		envValue       string
		remote         string
		expectTrusted  bool
		expectNonEmpty bool
	}{
		{"default loopback v4", "", "127.0.0.1:54321", true, true},
		{"default loopback v6", "", "[::1]:54321", true, true},
		{"default rejects public", "", "203.0.113.7:54321", false, true},
		{"explicit single IP", "192.168.1.10", "192.168.1.10:1234", true, true},
		{"explicit single IP wrong", "192.168.1.10", "192.168.1.11:1234", false, true},
		{"explicit CIDR", "10.0.0.0/8", "10.5.6.7:1234", true, true},
		{"explicit CIDR rejects outside", "10.0.0.0/8", "11.5.6.7:1234", false, true},
		{"multi-CIDR", "10.0.0.0/8,192.168.0.0/16", "192.168.42.1:1234", true, true},
		{"invalid entry skipped", "not-an-ip,127.0.0.1", "127.0.0.1:1234", true, true},
		{"all invalid means empty", "not-an-ip", "127.0.0.1:1234", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth.ResetHeaderAuthConfigForTest()
			t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "1")
			t.Setenv("PHOTOVIEW_HEADER_AUTH_TRUSTED_PROXIES", tc.envValue)
			t.Cleanup(auth.ResetHeaderAuthConfigForTest)

			cfg := auth.GetHeaderAuthConfig()
			assert.Equal(t, tc.expectNonEmpty, len(cfg.TrustedProxies) > 0,
				"trusted proxies non-empty expectation")
			assert.Equal(t, tc.expectTrusted, cfg.IsTrustedRemote(tc.remote))
		})
	}
}

func TestHeaderAuthConfig_DefaultUsernameHeader(t *testing.T) {
	auth.ResetHeaderAuthConfigForTest()
	t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "1")
	t.Setenv("PHOTOVIEW_HEADER_AUTH_USERNAME_HEADER", "")
	t.Cleanup(auth.ResetHeaderAuthConfigForTest)

	cfg := auth.GetHeaderAuthConfig()
	assert.Equal(t, "Remote-User", cfg.UsernameHeader)
}

// runRequest fires req through dataloader+auth middleware and returns the
// recorded response together with the user the resolvers would observe.
func runRequest(db *gorm.DB, req *http.Request) (*httptest.ResponseRecorder, *models.User) {
	var observed *models.User
	leaf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = auth.UserFromContext(r.Context())
	})
	full := dataloader.Middleware(db)(auth.Middleware(db)(leaf))
	rec := httptest.NewRecorder()
	full.ServeHTTP(rec, req)
	return rec, observed
}

func TestHeaderAuth(t *testing.T) {
	// Make sure every subtest reads a fresh config and that we don't leak
	// envs into neighbouring tests in the package.
	t.Cleanup(func() {
		t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "")
		t.Setenv("PHOTOVIEW_HEADER_AUTH_USERNAME_HEADER", "")
		t.Setenv("PHOTOVIEW_HEADER_AUTH_TRUSTED_PROXIES", "")
		auth.ResetHeaderAuthConfigForTest()
	})

	db := test_utils.DatabaseTest(t)

	existingPassword := "irrelevant"
	existing, err := models.RegisterUser(db, "existing-sso-user", &existingPassword, false)
	require.NoError(t, err)

	t.Run("disabled by default", func(t *testing.T) {
		auth.ResetHeaderAuthConfigForTest()
		t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "")

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("Remote-User", "existing-sso-user")

		rec, observed := runRequest(db, req)

		assert.Equal(t, 200, rec.Code)
		assert.Nil(t, observed, "header auth must be a no-op when disabled")
		assert.Empty(t, rec.Result().Cookies(), "no cookie should be set when disabled")
	})

	t.Run("authenticates existing user from trusted proxy", func(t *testing.T) {
		auth.ResetHeaderAuthConfigForTest()
		t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "1")
		t.Setenv("PHOTOVIEW_HEADER_AUTH_TRUSTED_PROXIES", "127.0.0.1/32")

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("Remote-User", "existing-sso-user")

		rec, observed := runRequest(db, req)

		assert.Equal(t, 200, rec.Code)
		require.NotNil(t, observed)
		assert.Equal(t, existing.ID, observed.ID)
		assert.Equal(t, "existing-sso-user", observed.Username)

		var hasAuthCookie bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == "auth-token" && c.Value != "" {
				hasAuthCookie = true
			}
		}
		assert.True(t, hasAuthCookie, "expected Set-Cookie: auth-token on header-auth success")
	})

	t.Run("auto-provisions new user", func(t *testing.T) {
		auth.ResetHeaderAuthConfigForTest()
		t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "1")
		t.Setenv("PHOTOVIEW_HEADER_AUTH_TRUSTED_PROXIES", "127.0.0.1/32")

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("Remote-User", "brand-new-sso-user")

		rec, observed := runRequest(db, req)

		assert.Equal(t, 200, rec.Code)
		require.NotNil(t, observed)
		assert.Equal(t, "brand-new-sso-user", observed.Username)
		assert.False(t, observed.Admin, "auto-provisioned users must default to non-admin")
	})

	t.Run("rejects untrusted remote", func(t *testing.T) {
		auth.ResetHeaderAuthConfigForTest()
		t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "1")
		t.Setenv("PHOTOVIEW_HEADER_AUTH_TRUSTED_PROXIES", "127.0.0.1/32")

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.RemoteAddr = "203.0.113.7:54321"
		req.Header.Set("Remote-User", "existing-sso-user")

		rec, observed := runRequest(db, req)

		assert.Equal(t, 200, rec.Code)
		assert.Nil(t, observed, "untrusted remote must not be authenticated by header")
	})

	t.Run("custom username header is honored", func(t *testing.T) {
		auth.ResetHeaderAuthConfigForTest()
		t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "1")
		t.Setenv("PHOTOVIEW_HEADER_AUTH_USERNAME_HEADER", "X-Forwarded-User")
		t.Setenv("PHOTOVIEW_HEADER_AUTH_TRUSTED_PROXIES", "127.0.0.1/32")

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("X-Forwarded-User", "existing-sso-user")

		rec, observed := runRequest(db, req)

		assert.Equal(t, 200, rec.Code)
		require.NotNil(t, observed)
		assert.Equal(t, existing.ID, observed.ID)
	})

	t.Run("missing header on trusted remote is a no-op", func(t *testing.T) {
		auth.ResetHeaderAuthConfigForTest()
		t.Setenv("PHOTOVIEW_HEADER_AUTH_ENABLED", "1")
		t.Setenv("PHOTOVIEW_HEADER_AUTH_TRUSTED_PROXIES", "127.0.0.1/32")

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.RemoteAddr = "127.0.0.1:54321"

		rec, observed := runRequest(db, req)

		assert.Equal(t, 200, rec.Code)
		assert.Nil(t, observed)
	})
}
