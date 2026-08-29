package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	credentialproviderapi "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

const (
	serviceSlugAnnotation = "cloudsmith.io/service-slug"
	orgSlugAnnotation     = "cloudsmith.io/org-slug"
	maxResponseBodySize   = 1 << 20
	defaultCacheDuration  = time.Hour
)

type cloudsmithOIDCRequest struct {
	OIDCToken   string `json:"oidc_token"`
	ServiceSlug string `json:"service_slug"`
}

type cloudsmithOIDCResponse struct {
	Token string `json:"token"`
	Error string `json:"error,omitempty"`
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// CloudsmithCredentialProvider exchanges Kubernetes service account tokens for registry credentials.
type CloudsmithCredentialProvider struct {
	config     Config
	httpClient httpDoer
	marshal    func(any) ([]byte, error)
	now        func() time.Time
}

// NewCloudsmithCredentialProvider creates a provider with a reusable, bounded HTTP client.
func NewCloudsmithCredentialProvider(config Config) *CloudsmithCredentialProvider {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConns,
		IdleConnTimeout:     config.IdleConnTimeout,
	}

	if config.InsecureSkipVerify {
		klog.Warning("TLS certificate verification is disabled")
	}

	return &CloudsmithCredentialProvider{
		config: config,
		httpClient: &http.Client{
			Timeout:   config.HTTPTimeout,
			Transport: transport,
		},
		marshal: json.Marshal,
		now:     time.Now,
	}
}

// GetCredentials validates a v1 kubelet request and returns Cloudsmith registry credentials.
func (c *CloudsmithCredentialProvider) GetCredentials(
	ctx context.Context,
	request *credentialproviderapi.CredentialProviderRequest,
) (*credentialproviderapi.CredentialProviderResponse, error) {
	if request.APIVersion != credentialproviderapi.SchemeGroupVersion.String() {
		return nil, fmt.Errorf("unsupported credential provider API version %q", request.APIVersion)
	}
	if request.Kind != "CredentialProviderRequest" {
		return nil, fmt.Errorf("unsupported credential provider request kind %q", request.Kind)
	}
	if request.ServiceAccountToken == "" {
		return nil, fmt.Errorf("service account token is required")
	}

	config := c.configForRequest(request.ServiceAccountAnnotations)
	if config.ServiceSlug == "" {
		return nil, fmt.Errorf("service_slug is required")
	}
	if config.OrgSlug == "" {
		return nil, fmt.Errorf("org_slug is required")
	}

	registryHost, err := registryFromImage(request.Image)
	if err != nil {
		return nil, err
	}

	cloudsmithToken, err := c.exchangeTokenWithCloudsmith(ctx, config, request.ServiceAccountToken)
	if err != nil {
		return nil, fmt.Errorf("exchange token with Cloudsmith: %w", err)
	}

	cacheDuration := tokenCacheDuration(cloudsmithToken, c.now())
	return &credentialproviderapi.CredentialProviderResponse{
		TypeMeta: metav1.TypeMeta{
			APIVersion: request.APIVersion,
			Kind:       "CredentialProviderResponse",
		},
		CacheKeyType:  credentialproviderapi.ImagePluginCacheKeyType,
		CacheDuration: &metav1.Duration{Duration: cacheDuration},
		Auth: map[string]credentialproviderapi.AuthConfig{
			registryHost: {
				Username: "token",
				Password: cloudsmithToken,
			},
		},
	}, nil
}

func (c *CloudsmithCredentialProvider) configForRequest(annotations map[string]string) Config {
	config := c.config
	if value := annotations[serviceSlugAnnotation]; value != "" {
		config.ServiceSlug = value
	}
	if value := annotations[orgSlugAnnotation]; value != "" {
		config.OrgSlug = value
	}
	return config
}

func (c *CloudsmithCredentialProvider) exchangeTokenWithCloudsmith(
	ctx context.Context,
	config Config,
	oidcToken string,
) (string, error) {
	payload, err := c.marshal(cloudsmithOIDCRequest{
		OIDCToken:   oidcToken,
		ServiceSlug: config.ServiceSlug,
	})
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}

	endpoint := url.URL{
		Scheme: "https",
		Host:   config.APIHost,
		Path:   "/openid/" + url.PathEscape(config.OrgSlug) + "/",
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range config.Headers {
		request.Header.Set(name, value)
	}

	response, err := c.doWithRetry(ctx, request)
	if err != nil {
		return "", err
	}

	body, readErr := readLimitedBody(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		return "", fmt.Errorf("read response: %w", readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close response: %w", closeErr)
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("cloudsmith API returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	var cloudsmithResponse cloudsmithOIDCResponse
	if err := json.Unmarshal(body, &cloudsmithResponse); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if cloudsmithResponse.Error != "" {
		return "", fmt.Errorf("cloudsmith API returned an error: %s", cloudsmithResponse.Error)
	}
	if cloudsmithResponse.Token == "" {
		return "", fmt.Errorf("cloudsmith API returned an empty token")
	}
	return cloudsmithResponse.Token, nil
}

func (c *CloudsmithCredentialProvider) doWithRetry(
	ctx context.Context,
	request *http.Request,
) (*http.Response, error) {
	if request.Body != nil && request.GetBody == nil {
		return nil, fmt.Errorf("request body cannot be replayed")
	}

	backoff := wait.Backoff{
		Duration: c.config.RetryBackoffDuration,
		Factor:   c.config.RetryBackoffFactor,
		Jitter:   c.config.RetryBackoffJitter,
		Steps:    c.config.MaxRetryAttempts,
		Cap:      c.config.RetryBackoffCap,
	}

	var response *http.Response
	var lastErr error
	var attempts int
	err := wait.ExponentialBackoffWithContext(ctx, backoff, func(attemptCtx context.Context) (bool, error) {
		attempts++
		attempt := request.Clone(attemptCtx)
		if request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				return false, fmt.Errorf("recreate request body: %w", err)
			}
			attempt.Body = body
		}

		var err error
		response, err = c.httpClient.Do(attempt)
		if err != nil {
			if response != nil && response.Body != nil {
				err = errors.Join(err, response.Body.Close())
			}
			lastErr = err
			return false, nil
		}
		if response.StatusCode != http.StatusTooManyRequests && response.StatusCode < http.StatusInternalServerError {
			return true, nil
		}

		body, readErr := readLimitedBody(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("read retryable HTTP %d response: %w", response.StatusCode, readErr)
		} else if closeErr != nil {
			lastErr = fmt.Errorf("close retryable HTTP %d response: %w", response.StatusCode, closeErr)
		} else {
			lastErr = fmt.Errorf("cloudsmith API returned retryable HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
		}
		return false, nil
	})
	if err == nil {
		return response, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("request failed after %d attempts: %w", attempts, lastErr)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("request interrupted: %w", err)
	}
	return nil, fmt.Errorf("retry request: %w", err)
}

func readLimitedBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBodySize {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxResponseBodySize)
	}
	return body, nil
}

func registryFromImage(image string) (string, error) {
	if strings.Contains(image, "://") {
		return "", fmt.Errorf("invalid image reference %q: expected registry/path", image)
	}
	registry, _, found := strings.Cut(image, "/")
	if !found || registry == "" {
		return "", fmt.Errorf("invalid image reference %q: expected registry/path", image)
	}
	return registry, nil
}

func tokenCacheDuration(tokenString string, now time.Time) time.Duration {
	expiration, err := parseTokenExpiration(tokenString)
	if err != nil {
		klog.V(4).InfoS("Token has no usable expiration; using default cache duration", "error", err)
		return defaultCacheDuration
	}

	lifetime := expiration.Sub(now)
	if lifetime <= 0 {
		return 0
	}
	return lifetime - lifetime/10
}

func parseTokenExpiration(tokenString string) (time.Time, error) {
	claims := jwt.MapClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(tokenString, claims)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse JWT: %w", err)
	}
	expiration, err := claims.GetExpirationTime()
	if err != nil {
		return time.Time{}, fmt.Errorf("read JWT expiration: %w", err)
	}
	if expiration == nil {
		return time.Time{}, fmt.Errorf("JWT is missing exp claim")
	}
	return expiration.Time, nil
}
