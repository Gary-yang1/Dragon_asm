package httpx

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimitConfig describes a token bucket applied per client key.
//
// Rate is how many requests refill per Window; Burst is how many may be spent
// at once. MaxKeys bounds memory so a caller rotating source addresses cannot
// grow the bucket table without limit.
type RateLimitConfig struct {
	Rate    int
	Window  time.Duration
	Burst   int
	MaxKeys int
}

// Login rate-limit defaults. Credential-stuffing needs thousands of attempts to
// pay off; 10 per minute per address leaves ample room for a human fumbling a
// password while making a grind impractical.
const (
	DefaultLoginRate    = 10
	DefaultLoginWindow  = time.Minute
	DefaultLoginBurst   = 10
	DefaultLimiterKeys  = 10000
	limiterIdleMultiple = 4
)

// LoginRateLimitConfig returns the default bucket for unauthenticated auth routes.
func LoginRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Rate:    DefaultLoginRate,
		Window:  DefaultLoginWindow,
		Burst:   DefaultLoginBurst,
		MaxKeys: DefaultLimiterKeys,
	}
}

// Callback bucket: a real scan run posts many callbacks in sequence, so this is
// deliberately generous. Its job is only to bound the unauthenticated
// audit-log write that every rejected callback performs — not to pace engines.
const (
	DefaultCallbackRate  = 600
	DefaultCallbackBurst = 120
)

// CallbackRateLimitConfig returns the bucket for the HMAC-authenticated engine
// callback route. Signature verification happens after an audit row is written,
// so an attacker who never possesses the secret can still force one INSERT per
// request; this caps that amplification.
func CallbackRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Rate:    DefaultCallbackRate,
		Window:  time.Minute,
		Burst:   DefaultCallbackBurst,
		MaxKeys: DefaultLimiterKeys,
	}
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// keyedRateLimiter is an in-process token bucket per key.
//
// In-process is deliberate: it needs no Redis round-trip on the login path and
// degrades safely across replicas — N replicas allow at most N× the configured
// rate, which still bounds a credential grind by orders of magnitude. Move it to
// a shared store only if a global guarantee becomes a requirement.
type keyedRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	perSec  float64
	burst   float64
	maxKeys int
	idleTTL time.Duration
	nowFn   func() time.Time
}

// normalize replaces unset or nonsensical fields with the login defaults so a
// zero-value config still produces a working limiter rather than one that
// divides by zero or blocks every request.
func (cfg RateLimitConfig) normalize() RateLimitConfig {
	if cfg.Window <= 0 {
		cfg.Window = DefaultLoginWindow
	}
	if cfg.Rate <= 0 {
		cfg.Rate = DefaultLoginRate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = cfg.Rate
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = DefaultLimiterKeys
	}
	return cfg
}

func newKeyedRateLimiter(cfg RateLimitConfig, nowFn func() time.Time) *keyedRateLimiter {
	cfg = cfg.normalize()
	if nowFn == nil {
		nowFn = time.Now
	}
	perSec := float64(cfg.Rate) / cfg.Window.Seconds()
	return &keyedRateLimiter{
		buckets: make(map[string]*bucket),
		perSec:  perSec,
		burst:   float64(cfg.Burst),
		maxKeys: cfg.MaxKeys,
		idleTTL: time.Duration(limiterIdleMultiple) * cfg.Window,
		nowFn:   nowFn,
	}
}

// allow consumes one token for key, reporting whether the request may proceed.
func (l *keyedRateLimiter) allow(key string) bool {
	now := l.nowFn()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		l.evictLocked(now)
		b = &bucket{tokens: l.burst, lastSeen: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		if elapsed > 0 {
			b.tokens = minFloat(l.burst, b.tokens+elapsed*l.perSec)
		}
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictLocked keeps the bucket table bounded. It first drops keys idle long
// enough to have refilled completely (removing them loses no state), and only
// if that is not enough does it clear the table wholesale — a coarse reset that
// briefly forgives in-flight offenders but never lets memory grow unbounded.
func (l *keyedRateLimiter) evictLocked(now time.Time) {
	if len(l.buckets) < l.maxKeys {
		return
	}
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) >= l.idleTTL {
			delete(l.buckets, key)
		}
	}
	if len(l.buckets) >= l.maxKeys {
		l.buckets = make(map[string]*bucket)
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// RateLimitByIP throttles requests per client address and answers 429 once a
// bucket is empty. Mount it on unauthenticated routes (login, token refresh)
// where there is no account to attribute abuse to.
//
// The key is c.ClientIP(), which is only trustworthy when trusted proxies are
// configured — see SetTrustedProxiesFromEnv. With the default (trust nothing)
// it is the peer address and cannot be forged.
func RateLimitByIP(cfg RateLimitConfig) gin.HandlerFunc {
	cfg = cfg.normalize()
	limiter := newKeyedRateLimiter(cfg, nil)
	retryAfter := strconv.Itoa(int(cfg.Window.Seconds()))
	return func(c *gin.Context) {
		if !limiter.allow(c.ClientIP()) {
			c.Header("Retry-After", retryAfter)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, ErrorResponse{
				RequestID: requestID(c),
				Error: ErrorDetail{
					Code:    ErrCodeTooManyRequests,
					Message: "too many requests; retry later",
				},
			})
			return
		}
		c.Next()
	}
}
