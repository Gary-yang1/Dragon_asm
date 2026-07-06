package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
)

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := auth.HashPassword("correct horse battery staple")
	require.NoError(t, err)
	assert.NotEqual(t, "correct horse battery staple", hash, "hash must not equal plaintext")

	assert.True(t, auth.CheckPassword(hash, "correct horse battery staple"))
	assert.False(t, auth.CheckPassword(hash, "wrong password"))
}

func TestCheckPasswordMalformedHash(t *testing.T) {
	// A non-bcrypt string must not authenticate anything and must not panic.
	assert.False(t, auth.CheckPassword("not-a-bcrypt-hash", "anything"))
	assert.False(t, auth.CheckPassword("", ""))
}

func TestHashPasswordDistinctSalts(t *testing.T) {
	h1, err := auth.HashPassword("same")
	require.NoError(t, err)
	h2, err := auth.HashPassword("same")
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "bcrypt salts each hash independently")
}
