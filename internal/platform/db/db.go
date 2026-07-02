// Package db provides MySQL connection management for the ASM platform.
//
// The driver is registered via a blank import. Secrets are read from the
// environment (DB_PASSWORD) and are never logged. Open returns a pinged pool
// suitable for handing to sqlc-generated queries.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Config holds MySQL connection parameters. In production these come from the
// environment via LoadConfigFromEnv.
type Config struct {
	Host            string
	Port            int
	User            string
	Password        string
	DBName          string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// LoadConfigFromEnv reads DB_* env vars with safe, non-secret defaults. The
// password has no default: it must be supplied via DB_PASSWORD.
func LoadConfigFromEnv() Config {
	return Config{
		Host:            envOr("DB_HOST", "localhost"),
		Port:            envInt("DB_PORT", 3306),
		User:            envOr("DB_USER", "asm"),
		Password:        os.Getenv("DB_PASSWORD"),
		DBName:          envOr("DB_NAME", "asm"),
		MaxOpenConns:    envInt("DB_MAX_OPEN_CONNS", 25),
		MaxIdleConns:    envInt("DB_MAX_IDLE_CONNS", 5),
		ConnMaxLifetime: envDuration("DB_CONN_MAX_LIFETIME", 30*time.Minute),
	}
}

// Open returns a pinged *sql.DB backed by the MySQL driver. parseTime maps
// DATETIME columns to time.Time and loc=UTC keeps timestamps zone-stable; the
// soft-delete sentinel '1970-01-01 00:00:00.000' therefore round-trips cleanly.
func Open(cfg Config) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC&charset=utf8mb4",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName,
	)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open mysql: %w", err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("db: ping mysql: %w", err)
	}
	return db, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
