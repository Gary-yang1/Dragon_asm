// Package auth provides JWT access/refresh token management and the Gin
// authentication/authorization middleware used by the ASM API.
//
// Secrets are sourced from the environment (JWT_ACCESS_SECRET /
// JWT_REFRESH_SECRET) and are never hardcoded. Tokens are signed with HS256,
// and verification pins the algorithm to HS256 to prevent alg-confusion
// attacks (e.g. alg=none or RS256-signed tokens being validated as HMAC).
package auth

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultAccessTTL and DefaultRefreshTTL are used when the corresponding env
// vars are unset. minSecretLen is the minimum accepted HS256 secret length
// (256 bits, per RFC 8729 §3.2); shorter secrets are rejected.
const (
	DefaultAccessTTL  = 15 * time.Minute
	DefaultRefreshTTL = 24 * time.Hour
	minSecretLen      = 32
)

// Sentinel errors for config loading and manager construction.
var (
	ErrSecretRequired    = errors.New("auth: JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be set")
	ErrSecretTooShort    = fmt.Errorf("auth: token signing secrets must be at least %d bytes", minSecretLen)
	ErrSecretsMustDiffer = errors.New("auth: JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ")
	ErrEmptyUserID       = errors.New("auth: token user id must not be empty")
)

// Claims are the custom JWT claims. UserID is the authenticated principal; the
// embedded RegisteredClaims carries issued-at / not-before / expiry.
type Claims struct {
	UserID string `json:"uid"`
	jwt.RegisteredClaims
}

// Config holds JWT manager configuration. Secrets must be supplied by the caller
// (typically from the environment); a zero TTL adopts the corresponding default.
type Config struct {
	AccessSecret  string
	RefreshSecret string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
}

// JWTManager issues and verifies HS256 access/refresh tokens using distinct
// secrets, so an access-token secret cannot validate a refresh token and vice
// versa.
type JWTManager struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

// NewManager validates the configuration and returns a JWTManager. Secrets
// shorter than minSecretLen are rejected, the access and refresh secrets must
// differ, and zero TTLs adopt the defaults.
//
// A negative TTL is accepted (and preserved) so callers/tests can mint
// already-expired tokens; in production TTLs must be positive.
func NewManager(cfg Config) (*JWTManager, error) {
	if len(cfg.AccessSecret) < minSecretLen || len(cfg.RefreshSecret) < minSecretLen {
		return nil, ErrSecretTooShort
	}
	if cfg.AccessSecret == cfg.RefreshSecret {
		// Distinct secrets are mandatory: there is no token-type claim, so a
		// shared secret would let a refresh token validate as an access token.
		return nil, ErrSecretsMustDiffer
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = DefaultAccessTTL
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = DefaultRefreshTTL
	}
	return &JWTManager{
		accessSecret:  []byte(cfg.AccessSecret),
		refreshSecret: []byte(cfg.RefreshSecret),
		accessTTL:     cfg.AccessTTL,
		refreshTTL:    cfg.RefreshTTL,
	}, nil
}

func (m *JWTManager) issue(secret []byte, ttl time.Duration, userID string) (string, error) {
	if userID == "" {
		return "", ErrEmptyUserID
	}
	now := time.Now()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// IssueAccessToken signs a short-lived access token for the given user.
func (m *JWTManager) IssueAccessToken(userID string) (string, error) {
	return m.issue(m.accessSecret, m.accessTTL, userID)
}

// IssueRefreshToken signs a longer-lived refresh token for the given user.
func (m *JWTManager) IssueRefreshToken(userID string) (string, error) {
	return m.issue(m.refreshSecret, m.refreshTTL, userID)
}

func (m *JWTManager) parse(secret []byte, tokenStr string) (*Claims, error) {
	claims := &Claims{}
	// WithValidMethods pins HS256 and WithExpirationRequired rejects tokens
	// without an expiry. The keyFunc additionally asserts the method is HMAC
	// before returning the key (defense-in-depth against alg confusion).
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// ParseAccessToken verifies an access token's signature and expiry.
func (m *JWTManager) ParseAccessToken(tokenStr string) (*Claims, error) {
	return m.parse(m.accessSecret, tokenStr)
}

// ParseRefreshToken verifies a refresh token's signature and expiry.
func (m *JWTManager) ParseRefreshToken(tokenStr string) (*Claims, error) {
	return m.parse(m.refreshSecret, tokenStr)
}

// LoadConfigFromEnv builds a Config from the environment. It returns
// ErrSecretRequired if either secret is empty; TTLs fall back to defaults when
// unset or unparseable.
func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		AccessSecret:  os.Getenv("JWT_ACCESS_SECRET"),
		RefreshSecret: os.Getenv("JWT_REFRESH_SECRET"),
		AccessTTL:     envDuration("JWT_ACCESS_TTL", DefaultAccessTTL),
		RefreshTTL:    envDuration("JWT_REFRESH_TTL", DefaultRefreshTTL),
	}
	if cfg.AccessSecret == "" || cfg.RefreshSecret == "" {
		return cfg, ErrSecretRequired
	}
	return cfg, nil
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
