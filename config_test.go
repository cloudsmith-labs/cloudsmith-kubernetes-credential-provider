package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigFromEnvironment(t *testing.T) {
	t.Setenv("CLOUDSMITH_API_HOST", "api.example.test:8443")
	t.Setenv("CLOUDSMITH_ORG_SLUG", "example-org")
	t.Setenv("CLOUDSMITH_SERVICE_SLUG", "example-service")
	t.Setenv("CLOUDSMITH_HTTP_TIMEOUT", "12s")

	config, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if config.APIHost != "api.example.test:8443" {
		t.Errorf("APIHost = %q", config.APIHost)
	}
	if config.OrgSlug != "example-org" || config.ServiceSlug != "example-service" {
		t.Errorf("slugs = %q/%q", config.OrgSlug, config.ServiceSlug)
	}
	if config.HTTPTimeout != 12*time.Second {
		t.Errorf("HTTPTimeout = %s", config.HTTPTimeout)
	}
}

func TestLoadConfigHeaderEnvironmentVariables(t *testing.T) {
	t.Setenv("CLOUDSMITH_HEADER_X_CUSTOM_AUTH", "env-token")
	config, err := LoadConfig(writeConfig(t, "headers:\n  X-Other: file-value\n"))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if config.Headers["X-Custom-Auth"] != "env-token" {
		t.Errorf("Headers[X-Custom-Auth] = %q", config.Headers["X-Custom-Auth"])
	}
	if config.Headers["X-Other"] != "file-value" {
		t.Errorf("Headers[X-Other] = %q", config.Headers["X-Other"])
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "API host URL", mutate: func(config *Config) { config.APIHost = "https://api.example.test/path" }, want: "api_host"},
		{name: "empty API host", mutate: func(config *Config) { config.APIHost = "" }, want: "api_host"},
		{name: "timeout", mutate: func(config *Config) { config.HTTPTimeout = 0 }, want: "http_timeout"},
		{name: "retry attempts", mutate: func(config *Config) { config.MaxRetryAttempts = 0 }, want: "max_retry_attempts"},
		{name: "backoff factor", mutate: func(config *Config) { config.RetryBackoffFactor = 0.5 }, want: "retry_backoff_factor"},
		{name: "jitter", mutate: func(config *Config) { config.RetryBackoffJitter = 2 }, want: "retry_backoff_jitter"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig()
			test.mutate(&config)
			err := config.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestLoadConfigFilesAndErrors(t *testing.T) {
	t.Run("explicit file and nil headers", func(t *testing.T) {
		config, err := LoadConfig(writeConfig(t, "headers:\n"))
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.Headers == nil {
			t.Fatal("Headers = nil")
		}
	})

	t.Run("missing explicit file", func(t *testing.T) {
		_, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
		if err == nil || !strings.Contains(err.Error(), "read config file") {
			t.Fatalf("LoadConfig() error = %v", err)
		}
	})

	t.Run("ignores working directory config", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile(defaultConfigName+".yaml", []byte("headers: ["), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		_, err := LoadConfig("")
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
	})

	t.Run("malformed default file", func(t *testing.T) {
		configDir := t.TempDir()
		oldPaths := defaultConfigPaths
		defaultConfigPaths = []string{configDir}
		t.Cleanup(func() { defaultConfigPaths = oldPaths })
		if err := os.WriteFile(filepath.Join(configDir, defaultConfigName+".yaml"), []byte("headers: ["), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		_, err := LoadConfig("")
		if err == nil || !strings.Contains(err.Error(), "read config file") {
			t.Fatalf("LoadConfig() error = %v", err)
		}
	})

	t.Run("decode error", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, "http_timeout: []\n"))
		if err == nil || !strings.Contains(err.Error(), "decode configuration") {
			t.Fatalf("LoadConfig() error = %v", err)
		}
	})

	t.Run("validation error", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, "http_timeout: 0s\n"))
		if err == nil || !strings.Contains(err.Error(), "http_timeout") {
			t.Fatalf("LoadConfig() error = %v", err)
		}
	})
}

func TestRemainingConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "max idle connections", mutate: func(config *Config) { config.MaxIdleConns = 0 }, want: "max_idle_conns"},
		{name: "idle timeout", mutate: func(config *Config) { config.IdleConnTimeout = 0 }, want: "idle_conn_timeout"},
		{name: "backoff duration", mutate: func(config *Config) { config.RetryBackoffDuration = 0 }, want: "retry_backoff_duration"},
		{name: "backoff cap", mutate: func(config *Config) { config.RetryBackoffCap = 0 }, want: "retry_backoff_cap"},
		{name: "valid", mutate: func(*Config) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig()
			test.mutate(&config)
			err := config.Validate()
			if test.want == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestConfigNormalize(t *testing.T) {
	config := Config{}
	config.normalize()
	if config.Headers == nil {
		t.Fatal("Headers = nil")
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
