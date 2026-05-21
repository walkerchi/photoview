package auth

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/photoview/photoview/api/dataloader"
	"github.com/photoview/photoview/api/graphql/models"
	"github.com/photoview/photoview/api/log"
	"gorm.io/gorm"
)

var ErrUnauthorized = errors.New("unauthorized")
var bearerRegex = regexp.MustCompile("^(?i)Bearer ([a-zA-Z0-9]{24})$")

const INVALID_AUTH_TOKEN = "invalid authorization token"
const INTERNAL_SERVER_ERROR = "internal server error"

// A private key for context that only this package can access. This is important
// to prevent collisions between different context uses
var userCtxKey = &contextKey{"user"}

type contextKey struct {
	name string
}

// Middleware decodes the share session cookie and packs the session into context
func Middleware(db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			var ctxUser *models.User

			if tokenCookie, err := r.Cookie(AuthTokenCookieName); err == nil {
				loaders := dataloader.For(r.Context())
				if loaders == nil {
					log.Error(r.Context(), "Dataloader not available in HTTP context")
					http.Error(w, INTERNAL_SERVER_ERROR, http.StatusInternalServerError)
					return
				}

				user, err := loaders.UserFromAccessToken.Load(tokenCookie.Value)
				// Database errors are still surfaced as a 500 — that's a real
				// problem, not a stale session.
				if err != nil {
					log.Error(r.Context(), "Error loading user from token", "error", err)
					http.Error(w, INVALID_AUTH_TOKEN, http.StatusUnauthorized)
					return
				}

				if user != nil {
					ctxUser = user
				} else if !GetHeaderAuthConfig().Enabled {
					// In cookie-only mode, an unknown token means the session
					// was revoked — keep the legacy "kick the client" behaviour
					// so explicit token revocation still works.
					log.Error(r.Context(), "Token not found in database")
					http.Error(w, INVALID_AUTH_TOKEN, http.StatusUnauthorized)
					return
				}
				// SSO mode + stale cookie: fall through to header auth below so
				// the reverse proxy can transparently re-establish the session.
			}

			if ctxUser == nil {
				// No usable cookie: optionally accept a Remote-User header
				// injected by a trusted reverse proxy. This lets Authelia /
				// authentik / oauth2-proxy front Photoview as true SSO — the
				// proxy's identity becomes a Photoview session.
				user, err := applyHeaderAuth(db, w, r)
				if err != nil {
					log.Error(r.Context(), "Header auth failed", "error", err)
					http.Error(w, INTERNAL_SERVER_ERROR, http.StatusInternalServerError)
					return
				}
				if user != nil {
					ctxUser = user
				}
			}

			if ctxUser != nil {
				r = r.WithContext(AddUserToContext(r.Context(), ctxUser))
			} else {
				log.Info(r.Context(), "Did not find auth-token cookie")
			}

			next.ServeHTTP(w, r)
		})
	}
}

func AddUserToContext(ctx context.Context, user *models.User) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}

func TokenFromBearer(bearer *string) (*string, error) {
	matches := bearerRegex.FindStringSubmatch(*bearer)
	if len(matches) != 2 {
		return nil, errors.New("invalid bearer format")
	}

	token := matches[1]
	return &token, nil
}

// UserFromContext finds the user from the context. REQUIRES Middleware to have run.
func UserFromContext(ctx context.Context) *models.User {
	raw, _ := ctx.Value(userCtxKey).(*models.User)
	return raw
}

func AuthWebsocketInit() func(context.Context, transport.InitPayload) (context.Context, *transport.InitPayload, error) {
	return func(ctx context.Context, initPayload transport.InitPayload) (context.Context, *transport.InitPayload, error) {

		bearer, exists := initPayload["Authorization"].(string)
		if !exists {
			return ctx, nil, nil
		}

		token, err := TokenFromBearer(&bearer)
		if err != nil {
			log.Error(ctx, "Invalid bearer format (websocket)", "error", err)
			return nil, nil, err
		}

		loaders := dataloader.For(ctx)
		if loaders == nil {
			log.Error(ctx, "Dataloader not available in websocket context")
			return nil, nil, errors.New(INTERNAL_SERVER_ERROR)
		}

		user, err := loaders.UserFromAccessToken.Load(*token)
		if err != nil {
			log.Error(ctx, "Error loading user from token (websocket)", "error", err)
			return nil, nil, errors.New(INVALID_AUTH_TOKEN)
		}

		// Check if token exists in database
		if user == nil {
			log.Error(ctx, "Token not found in database (websocket)")
			return nil, nil, errors.New(INVALID_AUTH_TOKEN)
		}

		// put it in context
		userCtx := context.WithValue(ctx, userCtxKey, user)

		// and return it so the resolvers can see it
		// Return nil for the InitPayload acknowledgment (no custom ack payload needed)
		return userCtx, nil, nil
	}
}
