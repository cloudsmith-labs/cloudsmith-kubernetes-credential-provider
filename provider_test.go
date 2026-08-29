package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	credentialproviderapi "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

var errTest = errors.New("test error")

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

type readCloser struct {
	reader   io.Reader
	closeErr error
}

func (r readCloser) Read(data []byte) (int, error) {
	return r.reader.Read(data)
}

func (r readCloser) Close() error {
	return r.closeErr
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errTest
}

func TestGetCredentials(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	token := unsignedToken(t, now.Add(time.Hour))
	var attempts atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempt := attempts.Add(1)
		if attempt == 1 {
			http.Error(writer, "try again", http.StatusServiceUnavailable)
			return
		}
		if request.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", request.Method)
		}
		if request.URL.Path != "/openid/request-org/" {
			t.Errorf("path = %q, want /openid/request-org/", request.URL.Path)
		}
		if request.Header.Get("X-Cloudsmith-Test") != "value" {
			t.Errorf("custom header = %q, want value", request.Header.Get("X-Cloudsmith-Test"))
		}
		var payload cloudsmithOIDCRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload.OIDCToken != "service-account-token" || payload.ServiceSlug != "request-service" {
			t.Errorf("payload = %#v", payload)
		}
		writer.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(writer).Encode(cloudsmithOIDCResponse{Token: token}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	config := testConfig()
	config.APIHost = strings.TrimPrefix(server.URL, "https://")
	config.Headers = map[string]string{"X-Cloudsmith-Test": "value"}
	config.RetryBackoffDuration = time.Nanosecond
	provider := NewCloudsmithCredentialProvider(config)
	provider.httpClient = server.Client()
	provider.now = func() time.Time { return now }

	response, err := provider.GetCredentials(context.Background(), &credentialproviderapi.CredentialProviderRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: credentialproviderapi.SchemeGroupVersion.String(),
			Kind:       "CredentialProviderRequest",
		},
		Image:               "docker.cloudsmith.io/acme/repo/image:latest",
		ServiceAccountToken: "service-account-token",
		ServiceAccountAnnotations: map[string]string{
			serviceSlugAnnotation:        "request-service",
			orgSlugAnnotation:            "request-org",
			"cloudsmith.io/api-host":     "attacker.example",
			"cloudsmith.io/unrecognized": "ignored",
		},
	})
	if err != nil {
		t.Fatalf("GetCredentials() error = %v", err)
	}

	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
	if response.APIVersion != credentialproviderapi.SchemeGroupVersion.String() {
		t.Errorf("apiVersion = %q", response.APIVersion)
	}
	if response.Kind != "CredentialProviderResponse" {
		t.Errorf("kind = %q", response.Kind)
	}
	if response.CacheKeyType != credentialproviderapi.ImagePluginCacheKeyType {
		t.Errorf("cacheKeyType = %q", response.CacheKeyType)
	}
	if response.CacheDuration.Duration != 54*time.Minute {
		t.Errorf("cacheDuration = %s, want 54m", response.CacheDuration.Duration)
	}
	auth := response.Auth["docker.cloudsmith.io"]
	if auth.Username != "token" || auth.Password != token {
		t.Errorf("auth = %#v", auth)
	}
	if provider.config.ServiceSlug != "default-service" || provider.config.OrgSlug != "default-org" {
		t.Errorf("base configuration was mutated: %#v", provider.config)
	}
}

func TestGetCredentialsValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request credentialproviderapi.CredentialProviderRequest
		want    string
	}{
		{
			name: "API version",
			request: credentialproviderapi.CredentialProviderRequest{
				TypeMeta: metav1.TypeMeta{APIVersion: "credentialprovider.kubelet.k8s.io/v1alpha1", Kind: "CredentialProviderRequest"},
			},
			want: "unsupported credential provider API version",
		},
		{
			name: "kind",
			request: credentialproviderapi.CredentialProviderRequest{
				TypeMeta: metav1.TypeMeta{APIVersion: credentialproviderapi.SchemeGroupVersion.String(), Kind: "Other"},
			},
			want: "unsupported credential provider request kind",
		},
		{
			name: "token",
			request: credentialproviderapi.CredentialProviderRequest{
				TypeMeta: metav1.TypeMeta{APIVersion: credentialproviderapi.SchemeGroupVersion.String(), Kind: "CredentialProviderRequest"},
			},
			want: "service account token is required",
		},
	}

	provider := NewCloudsmithCredentialProvider(testConfig())
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := provider.GetCredentials(context.Background(), &test.request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("GetCredentials() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestTokenCacheDuration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		token string
		want  time.Duration
	}{
		{name: "valid token", token: unsignedToken(t, now.Add(10*time.Minute)), want: 9 * time.Minute},
		{name: "expired token", token: unsignedToken(t, now.Add(-time.Minute)), want: 0},
		{name: "not a JWT", token: "opaque-token", want: time.Hour},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := tokenCacheDuration(test.token, now); got != test.want {
				t.Fatalf("tokenCacheDuration() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestRegistryFromImage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		image   string
		want    string
		wantErr bool
	}{
		{image: "docker.cloudsmith.io/org/repo/image:tag", want: "docker.cloudsmith.io"},
		{image: "docker.cloudsmith.io:5000/org/image@sha256:123", want: "docker.cloudsmith.io:5000"},
		{image: "ubuntu:latest", wantErr: true},
		{image: "https://docker.cloudsmith.io/org/image", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.image, func(t *testing.T) {
			t.Parallel()
			got, err := registryFromImage(test.image)
			if (err != nil) != test.wantErr {
				t.Fatalf("registryFromImage() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("registryFromImage() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProviderAdditionalPaths(t *testing.T) {
	t.Run("insecure transport", func(t *testing.T) {
		config := testConfig()
		config.InsecureSkipVerify = true
		provider := NewCloudsmithCredentialProvider(config)
		if provider.httpClient == nil {
			t.Fatal("httpClient = nil")
		}
	})

	valid := credentialproviderapi.CredentialProviderRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: credentialproviderapi.SchemeGroupVersion.String(),
			Kind:       "CredentialProviderRequest",
		},
		Image:               "registry.example/repo/image",
		ServiceAccountToken: "oidc",
	}
	tests := []struct {
		name   string
		mutate func(*Config, *credentialproviderapi.CredentialProviderRequest)
		want   string
	}{
		{
			name: "service slug",
			mutate: func(config *Config, _ *credentialproviderapi.CredentialProviderRequest) {
				config.ServiceSlug = ""
			},
			want: "service_slug",
		},
		{
			name: "org slug",
			mutate: func(config *Config, _ *credentialproviderapi.CredentialProviderRequest) {
				config.OrgSlug = ""
			},
			want: "org_slug",
		},
		{
			name: "image",
			mutate: func(_ *Config, request *credentialproviderapi.CredentialProviderRequest) {
				request.Image = "ubuntu"
			},
			want: "invalid image",
		},
		{
			name: "exchange",
			mutate: func(config *Config, _ *credentialproviderapi.CredentialProviderRequest) {
				config.MaxRetryAttempts = 1
			},
			want: "exchange token with Cloudsmith",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig()
			request := valid
			test.mutate(&config, &request)
			provider := NewCloudsmithCredentialProvider(config)
			provider.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
				return nil, errTest
			})
			_, err := provider.GetCredentials(context.Background(), &request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("GetCredentials() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestExchangeTokenResponses(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      io.Reader
		closeErr  error
		want      string
		wantToken string
	}{
		{name: "read error", status: http.StatusOK, body: errorReader{}, want: "read response"},
		{name: "close error", status: http.StatusOK, body: strings.NewReader(`{"token":"value"}`), closeErr: errTest, want: "close response"},
		{name: "HTTP error", status: http.StatusBadRequest, body: strings.NewReader(" bad request \n"), want: "HTTP 400: bad request"},
		{name: "invalid JSON", status: http.StatusOK, body: strings.NewReader("{"), want: "decode response"},
		{name: "API error", status: http.StatusOK, body: strings.NewReader(`{"error":"denied"}`), want: "returned an error: denied"},
		{name: "empty token", status: http.StatusOK, body: strings.NewReader(`{}`), want: "empty token"},
		{name: "success", status: http.StatusOK, body: strings.NewReader(`{"token":"value"}`), wantToken: "value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := NewCloudsmithCredentialProvider(testConfig())
			provider.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: test.status,
					Body:       readCloser{reader: test.body, closeErr: test.closeErr},
				}, nil
			})
			token, err := provider.exchangeTokenWithCloudsmith(context.Background(), testConfig(), "oidc")
			if test.wantToken != "" && (err != nil || token != test.wantToken) {
				t.Fatalf("exchangeTokenWithCloudsmith() = %q, %v", token, err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("exchangeTokenWithCloudsmith() error = %v, want containing %q", err, test.want)
			}
		})
	}

	t.Run("marshal error", func(t *testing.T) {
		provider := NewCloudsmithCredentialProvider(testConfig())
		provider.marshal = func(any) ([]byte, error) { return nil, errTest }
		_, err := provider.exchangeTokenWithCloudsmith(context.Background(), testConfig(), "oidc")
		if !errors.Is(err, errTest) {
			t.Fatalf("exchangeTokenWithCloudsmith() error = %v", err)
		}
	})

	t.Run("create request error", func(t *testing.T) {
		config := testConfig()
		config.APIHost = "bad\nhost"
		provider := NewCloudsmithCredentialProvider(config)
		_, err := provider.exchangeTokenWithCloudsmith(context.Background(), config, "oidc")
		if err == nil || !strings.Contains(err.Error(), "create request") {
			t.Fatalf("exchangeTokenWithCloudsmith() error = %v", err)
		}
	})
}

func TestDoWithRetryErrors(t *testing.T) {
	t.Run("unreplayable body", func(t *testing.T) {
		provider := NewCloudsmithCredentialProvider(testConfig())
		request, err := http.NewRequest(http.MethodPost, "https://example.test", strings.NewReader("body"))
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		request.GetBody = nil
		if _, err := provider.doWithRetry(context.Background(), request); err == nil {
			t.Fatal("doWithRetry() error = nil")
		}
	})

	t.Run("recreate body", func(t *testing.T) {
		provider := NewCloudsmithCredentialProvider(testConfig())
		request, err := http.NewRequest(http.MethodPost, "https://example.test", strings.NewReader("body"))
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		request.GetBody = func() (io.ReadCloser, error) { return nil, errTest }
		_, err = provider.doWithRetry(context.Background(), request)
		if !errors.Is(err, errTest) {
			t.Fatalf("doWithRetry() error = %v", err)
		}
	})

	t.Run("transport error with response", func(t *testing.T) {
		config := testConfig()
		config.MaxRetryAttempts = 1
		provider := NewCloudsmithCredentialProvider(config)
		provider.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{Body: readCloser{reader: strings.NewReader(""), closeErr: errTest}}, errTest
		})
		request, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
		_, err := provider.doWithRetry(context.Background(), request)
		if err == nil || !strings.Contains(err.Error(), "failed after 1 attempts") {
			t.Fatalf("doWithRetry() error = %v", err)
		}
	})

	for _, test := range []struct {
		name string
		body io.ReadCloser
		want string
	}{
		{name: "retry body read", body: readCloser{reader: errorReader{}}, want: "read retryable"},
		{name: "retry body close", body: readCloser{reader: strings.NewReader("busy"), closeErr: errTest}, want: "close retryable"},
		{name: "retry exhausted", body: readCloser{reader: strings.NewReader("busy")}, want: "retryable HTTP 503: busy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig()
			config.MaxRetryAttempts = 1
			provider := NewCloudsmithCredentialProvider(config)
			provider.httpClient = doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: test.body}, nil
			})
			request, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
			_, err := provider.doWithRetry(context.Background(), request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("doWithRetry() error = %v, want containing %q", err, test.want)
			}
		})
	}

	t.Run("cancelled", func(t *testing.T) {
		provider := NewCloudsmithCredentialProvider(testConfig())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
		_, err := provider.doWithRetry(ctx, request)
		if err == nil || !strings.Contains(err.Error(), "request interrupted") {
			t.Fatalf("doWithRetry() error = %v", err)
		}
	})
}

func TestReadLimitedBody(t *testing.T) {
	if _, err := readLimitedBody(errorReader{}); !errors.Is(err, errTest) {
		t.Fatalf("readLimitedBody() error = %v", err)
	}
	if _, err := readLimitedBody(strings.NewReader(strings.Repeat("x", maxResponseBodySize+1))); err == nil {
		t.Fatal("readLimitedBody() oversized error = nil")
	}
	body, err := readLimitedBody(strings.NewReader("ok"))
	if err != nil || string(body) != "ok" {
		t.Fatalf("readLimitedBody() = %q, %v", body, err)
	}
}

func TestParseTokenExpirationErrors(t *testing.T) {
	for _, test := range []struct {
		name  string
		token string
		want  string
	}{
		{name: "invalid expiration", token: unsignedTokenWithClaims(t, jwt.MapClaims{"exp": "tomorrow"}), want: "read JWT expiration"},
		{name: "missing expiration", token: unsignedTokenWithClaims(t, jwt.MapClaims{}), want: "missing exp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseTokenExpiration(test.token)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseTokenExpiration() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func unsignedToken(t *testing.T, expiration time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"exp": expiration.Unix()})
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("create test JWT: %v", err)
	}
	return signed
}

func testConfig() Config {
	return Config{
		APIHost:              "api.cloudsmith.io",
		ServiceSlug:          "default-service",
		OrgSlug:              "default-org",
		LogLevel:             "info",
		Headers:              map[string]string{},
		HTTPTimeout:          time.Second,
		MaxIdleConns:         2,
		IdleConnTimeout:      time.Second,
		MaxRetryAttempts:     3,
		RetryBackoffDuration: time.Millisecond,
		RetryBackoffFactor:   1,
		RetryBackoffCap:      time.Millisecond,
	}
}

func staticResponse(status int, body string) httpDoer {
	return doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})
}

func unsignedTokenWithClaims(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("create test JWT: %v", err)
	}
	return signed
}
