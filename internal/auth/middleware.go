package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

// CtxUserID and CtxProjectID are request-context keys populated by the
// middleware in this file. RequirePermission reads them to authorize a request.
const (
	CtxUserID    = "auth.user_id"
	CtxProjectID = "auth.project_id"
	// #nosec G101 -- this is a request-context key, not a credential.
	CtxMustChangePassword = "auth.must_change_password"
)

type userVersionResolver interface {
	GetByID(context.Context, uint64) (*User, error)
}

const bearerScheme = "Bearer "

// RequireAuth validates the `Authorization: Bearer <access_token>` header,
// verifies the JWT, and stores the user id in the request context.
//
// Any failure — a missing header, a malformed scheme, an invalid/expired token,
// or a token whose user id is empty — yields a 401 via the unified error
// envelope. The specific reason is not surfaced, to avoid leaking token state
// to an untrusted caller.
func RequireAuth(m *JWTManager, users ...userVersionResolver) gin.HandlerFunc {
	var resolver userVersionResolver
	if len(users) > 0 {
		resolver = users[0]
	}

	return func(c *gin.Context) {
		raw := c.GetHeader("Authorization")
		if !strings.HasPrefix(raw, bearerScheme) {
			httpx.Unauthorized(c)
			c.Abort()
			return
		}
		tokenStr := strings.TrimPrefix(raw, bearerScheme)
		if tokenStr == "" {
			httpx.Unauthorized(c)
			c.Abort()
			return
		}
		claims, err := m.ParseAccessToken(tokenStr)
		if err != nil {
			httpx.Unauthorized(c)
			c.Abort()
			return
		}
		if claims.UserID == "" {
			// Defense-in-depth: issuance rejects empty user ids, but a token
			// forged or minted by another issuer must not authenticate either.
			httpx.Unauthorized(c)
			c.Abort()
			return
		}

		if resolver != nil {
			uid, err := parseUserID(claims.UserID)
			if err != nil {
				httpx.Unauthorized(c)
				c.Abort()
				return
			}
			u, err := resolver.GetByID(c.Request.Context(), uid)
			if err != nil || !u.IsActive() || claims.AuthVersion != u.AuthVersion {
				httpx.Unauthorized(c)
				c.Abort()
				return
			}
			c.Set(CtxMustChangePassword, u.MustChangePassword)
		}
		c.Set(CtxUserID, claims.UserID)
		c.Next()
	}
}

// RequirePasswordChanged blocks business APIs while an account is using an
// administrator-issued temporary password. Authentication self-service routes
// are mounted on a separate group without this middleware.
func RequirePasswordChanged() gin.HandlerFunc {
	return func(c *gin.Context) {
		mustChange, _ := c.Get(CtxMustChangePassword)
		if required, _ := mustChange.(bool); required {
			httpx.Fail(c, http.StatusForbidden, ErrCodePasswordRequired, "password change required")
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequirePermission returns a middleware that enforces a Casbin permission for
// the current request. It reads the user id and project id previously stored in
// the context (by RequireAuth and a project-id source such as
// ProjectIDFromParam) and enforces (user, project, permission, "allow").
//
// A missing user id yields 401 (the route is protected but unauthenticated); a
// Casbin denial or enforce error yields 403. The required permission is declared
// per-route so each endpoint states its permission point explicitly.
func RequirePermission(enforcer *casbin.Enforcer, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := c.Get(CtxUserID)
		uid, _ := userID.(string)
		if !ok || uid == "" {
			httpx.Unauthorized(c)
			c.Abort()
			return
		}
		projectID, _ := c.Get(CtxProjectID)
		pid, _ := projectID.(string)

		allowed, err := enforcer.Enforce(uid, pid, permission, "allow")
		if err != nil || !allowed {
			httpx.Forbidden(c)
			c.Abort()
			return
		}
		c.Next()
	}
}

// ProjectIDFromParam stores the named URL path parameter as the project id in
// the context so RequirePermission can enforce per-project isolation. Mount it
// on routes that carry a :project_id segment.
func ProjectIDFromParam(param string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if v := c.Param(param); v != "" {
			c.Set(CtxProjectID, v)
		}
		c.Next()
	}
}
