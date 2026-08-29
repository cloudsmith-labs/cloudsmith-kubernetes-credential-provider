package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	defaultConfigName = "cloudsmith-kubernetes-credential-provider"
	envPrefix         = "CLOUDSMITH"
	headerEnvPrefix   = envPrefix + "_HEADER_"
)

var defaultConfigPaths = []string{"/etc/cloudsmith"}

// Config controls Cloudsmith token exchange and HTTP retry behavior.
type Config struct {
	APIHost            string            `mapstructure:"api_host"`
	ServiceSlug        string            `mapstructure:"service_slug"`
	OrgSlug            string            `mapstructure:"org_slug"`
	LogLevel           string            `mapstructure:"log_level"`
	InsecureSkipVerify bool              `mapstructure:"insecure_skip_verify"`
	Headers            map[string]string `mapstructure:"headers"`

	HTTPTimeout     time.Duration `mapstructure:"http_timeout"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	IdleConnTimeout time.Duration `mapstructure:"idle_conn_timeout"`

	MaxRetryAttempts     int           `mapstructure:"max_retry_attempts"`
	RetryBackoffDuration time.Duration `mapstructure:"retry_backoff_duration"`
	RetryBackoffFactor   float64       `mapstructure:"retry_backoff_factor"`
	RetryBackoffJitter   float64       `mapstructure:"retry_backoff_jitter"`
	RetryBackoffCap      time.Duration `mapstructure:"retry_backoff_cap"`
}

// LoadConfig reads defaults, an optional YAML file, and CLOUDSMITH_* environment variables.
func LoadConfig(configFile string) (Config, error) {
	v := viper.NewWithOptions(viper.ExperimentalBindStruct())
	v.SetConfigName(defaultConfigName)
	v.SetConfigType("yaml")
	for _, path := range defaultConfigPaths {
		v.AddConfigPath(path)
	}

	v.SetDefault("api_host", "api.cloudsmith.io")
	v.SetDefault("log_level", "info")
	v.SetDefault("insecure_skip_verify", false)
	v.SetDefault("headers", map[string]string{})
	v.SetDefault("http_timeout", 30*time.Second)
	v.SetDefault("max_idle_conns", 10)
	v.SetDefault("idle_conn_timeout", 30*time.Second)
	v.SetDefault("max_retry_attempts", 3)
	v.SetDefault("retry_backoff_duration", time.Second)
	v.SetDefault("retry_backoff_factor", 2.0)
	v.SetDefault("retry_backoff_jitter", 0.1)
	v.SetDefault("retry_backoff_cap", 30*time.Second)

	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read config file %q: %w", configFile, err)
		}
	} else if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return Config{}, fmt.Errorf("read config file: %w", err)
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	config.normalize()
	if err := config.Validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func (c *Config) normalize() {
	headers := make(map[string]string, len(c.Headers))
	for name, value := range c.Headers {
		headers[http.CanonicalHeaderKey(name)] = value
	}
	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, headerEnvPrefix) {
			continue
		}
		headerName := strings.ReplaceAll(strings.TrimPrefix(name, headerEnvPrefix), "_", "-")
		headers[http.CanonicalHeaderKey(headerName)] = value
	}
	c.Headers = headers
}

// Validate rejects unsafe or unusable provider settings.
func (c Config) Validate() error {
	apiURL, err := url.Parse("https://" + c.APIHost)
	if c.APIHost == "" || err != nil || apiURL.Host != c.APIHost || apiURL.Path != "" || apiURL.User != nil {
		return fmt.Errorf("api_host must be a host name with an optional port")
	}
	if c.HTTPTimeout <= 0 {
		return fmt.Errorf("http_timeout must be greater than zero")
	}
	if c.MaxIdleConns <= 0 {
		return fmt.Errorf("max_idle_conns must be greater than zero")
	}
	if c.IdleConnTimeout <= 0 {
		return fmt.Errorf("idle_conn_timeout must be greater than zero")
	}
	if c.MaxRetryAttempts <= 0 {
		return fmt.Errorf("max_retry_attempts must be greater than zero")
	}
	if c.RetryBackoffDuration <= 0 {
		return fmt.Errorf("retry_backoff_duration must be greater than zero")
	}
	if c.RetryBackoffFactor < 1 {
		return fmt.Errorf("retry_backoff_factor must be at least 1")
	}
	if c.RetryBackoffJitter < 0 || c.RetryBackoffJitter > 1 {
		return fmt.Errorf("retry_backoff_jitter must be between 0 and 1")
	}
	if c.RetryBackoffCap <= 0 {
		return fmt.Errorf("retry_backoff_cap must be greater than zero")
	}
	return nil
}
