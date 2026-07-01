package httpx

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Response is the unified success envelope.
type Response struct {
	RequestID string `json:"request_id"`
	Data      any    `json:"data"`
}

// ErrorDetail is the unified error envelope.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// ErrorResponse wraps ErrorDetail in the standard envelope.
type ErrorResponse struct {
	RequestID string      `json:"request_id"`
	Error     ErrorDetail `json:"error"`
}

// PageData is the generic pagination wrapper for list responses.
type PageData[T any] struct {
	Items      []T   `json:"items"`
	Total      int64 `json:"total"`
	PageSize   int   `json:"page_size"`
	PageNumber int   `json:"page_number"`
}

// CursorPageData is the cursor-based pagination wrapper for large tables.
type CursorPageData[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

// ErrCodeBadRequest and related constants are the standard HTTP-layer machine-readable codes
// returned in all API error responses.
const (
	ErrCodeBadRequest      = "BAD_REQUEST"
	ErrCodeUnauthorized    = "UNAUTHORIZED"
	ErrCodeForbidden       = "FORBIDDEN"
	ErrCodeNotFound        = "NOT_FOUND"
	ErrCodeConflict        = "CONFLICT"
	ErrCodeUnprocessable   = "UNPROCESSABLE_ENTITY"
	ErrCodeTooManyRequests = "TOO_MANY_REQUESTS"
	ErrCodeInternalServer  = "INTERNAL_SERVER_ERROR"
)

// ErrCodeProjectNotFound and related constants are business-domain error codes extended by each module.
const (
	ErrCodeProjectNotFound   = "PROJECT_NOT_FOUND"
	ErrCodeAssetNotFound     = "ASSET_NOT_FOUND"
	ErrCodeRiskNotFound      = "RISK_NOT_FOUND"
	ErrCodeTicketNotFound    = "TICKET_NOT_FOUND"
	ErrCodeInvalidTransition = "INVALID_STATE_TRANSITION"
	ErrCodeScopeExpired      = "SCOPE_EXPIRED"
	ErrCodeDangerousTarget   = "DANGEROUS_TARGET"
)

// ── Response helpers ──────────────────────────────────────────────────────────

// RequestIDKey is the context key for the request ID.
const RequestIDKey = "request_id"

func requestID(c *gin.Context) string {
	if id, ok := c.Get(RequestIDKey); ok {
		if s, ok := id.(string); ok && s != "" {
			return s
		}
	}
	return uuid.NewString()
}

// OK writes a 200 success response.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{RequestID: requestID(c), Data: data})
}

// Created writes a 201 success response.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, Response{RequestID: requestID(c), Data: data})
}

// NoContent writes a 204 response.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Fail writes an error response with the given HTTP status.
func Fail(c *gin.Context, status int, code, message string, details ...any) {
	var det any
	if len(details) > 0 {
		det = details[0]
	}
	c.JSON(status, ErrorResponse{
		RequestID: requestID(c),
		Error:     ErrorDetail{Code: code, Message: message, Details: det},
	})
}

// BadRequest writes a 400 response.
func BadRequest(c *gin.Context, message string, details ...any) {
	Fail(c, http.StatusBadRequest, ErrCodeBadRequest, message, details...)
}

// Unauthorized writes a 401 response.
func Unauthorized(c *gin.Context) {
	Fail(c, http.StatusUnauthorized, ErrCodeUnauthorized, "authentication required")
}

// Forbidden writes a 403 response.
func Forbidden(c *gin.Context) {
	Fail(c, http.StatusForbidden, ErrCodeForbidden, "permission denied")
}

// NotFound writes a 404 response.
func NotFound(c *gin.Context, code, message string) {
	Fail(c, http.StatusNotFound, code, message)
}

// Conflict writes a 409 response.
func Conflict(c *gin.Context, code, message string) {
	Fail(c, http.StatusConflict, code, message)
}

// Unprocessable writes a 422 response.
func Unprocessable(c *gin.Context, message string, details ...any) {
	Fail(c, http.StatusUnprocessableEntity, ErrCodeUnprocessable, message, details...)
}

// Internal writes a 500 response and avoids leaking internal detail to callers.
func Internal(c *gin.Context) {
	Fail(c, http.StatusInternalServerError, ErrCodeInternalServer, "an unexpected error occurred")
}
