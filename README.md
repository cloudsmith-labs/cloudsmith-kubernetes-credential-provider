# Cloudsmith Kubernetes Credential Provider

> [!IMPORTANT]
> **Beta:** This project tracks the maturity of
> [KEP-4412](https://kep.k8s.io/4412). Service account token support for kubelet
> image credential providers graduated to beta in Kubernetes 1.34 and remains
> beta in Kubernetes 1.37. This project will transition to stable when KEP-4412
> does.

This exec credential provider exchanges a pod-bound Kubernetes service account
token for short-lived Cloudsmith registry credentials. It implements the
`credentialprovider.kubelet.k8s.io/v1` protocol and avoids storing long-lived
image pull secrets in a cluster.

## Requirements

- Kubernetes 1.34 or later
- A Cloudsmith OIDC service configured to trust the cluster's service account
  issuer
- The provider binary installed on every node
- Kubelet access to the configured service account token audience

`KubeletServiceAccountTokenForCredentialProviders` is enabled by default from
Kubernetes 1.34. Operators can still disable it, so verify the feature gate if
kubelet does not invoke the provider.

## How it works

1. Kubelet requests a pod-bound service account token for the configured
   audience.
2. Kubelet invokes this binary and sends a
   `CredentialProviderRequest` through stdin.
3. The provider exchanges the token with Cloudsmith.
4. The provider returns short-lived registry credentials through stdout.

The example config uses `cacheType: Token`, the conservative beta caching mode.
The provider derives Cloudsmith credentials from the input token and limits
their cache duration to the returned token's lifetime.

## Provider configuration

Configure the provider with environment variables in the kubelet credential
provider config:

```yaml
apiVersion: kubelet.config.k8s.io/v1
kind: CredentialProviderConfig
providers:
  - name: cloudsmith-kubernetes-credential-provider
    matchImages:
      - "docker.cloudsmith.io"
    defaultCacheDuration: 1h
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    env:
      - name: CLOUDSMITH_ORG_SLUG
        value: example-org
      - name: CLOUDSMITH_SERVICE_SLUG
        value: example-service
    tokenAttributes:
      serviceAccountTokenAudience: cloudsmith
      cacheType: Token
      requireServiceAccount: true
      optionalServiceAccountAnnotationKeys:
        - cloudsmith.io/org-slug
        - cloudsmith.io/service-slug
```

The `cacheType` field is required from Kubernetes 1.34. Omitting it is an
alpha-to-beta breaking configuration change and prevents kubelet from starting.

### Settings

| Environment variable | Default | Description |
| --- | --- | --- |
| `CLOUDSMITH_API_HOST` | `api.cloudsmith.io` | Cloudsmith API host, optionally including a port |
| `CLOUDSMITH_ORG_SLUG` | | Default Cloudsmith organization slug |
| `CLOUDSMITH_SERVICE_SLUG` | | Default Cloudsmith OIDC service slug |
| `CLOUDSMITH_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, or `error` |
| `CLOUDSMITH_HTTP_TIMEOUT` | `30s` | Cloudsmith request timeout |
| `CLOUDSMITH_MAX_RETRY_ATTEMPTS` | `3` | Attempts for HTTP 429 and 5xx responses |
| `CLOUDSMITH_INSECURE_SKIP_VERIFY` | `false` | Disable TLS verification; development only |

You can also supply all settings in a YAML file and pass it with `--config`.
Set additional HTTP headers in that file:

```yaml
headers:
  X-Example-Header: value
```

You can also set a header with a `CLOUDSMITH_HEADER_*` environment variable.
For example, `CLOUDSMITH_HEADER_X_EXAMPLE_HEADER=value` sets `X-Example-Header`.

The `cloudsmith.io/org-slug` and `cloudsmith.io/service-slug` service account
annotations override their defaults for one request. The API host is deliberately
not annotation-configurable because service account owners must not be able to
redirect projected tokens to another host.

## Kubelet audience authorization

When `ServiceAccountNodeAudienceRestriction` is enabled, authorize nodes to
request the `cloudsmith` audience:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cloudsmith-credential-provider-audience
rules:
  - apiGroups: [""]
    resources: ["cloudsmith"]
    verbs: ["request-serviceaccounts-token-audience"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cloudsmith-credential-provider-audience
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cloudsmith-credential-provider-audience
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: system:nodes
```

Use `resourceNames` in the role to restrict access to specific service accounts
when your cluster's authorization policy requires tighter scope.

## Install

Download an archive for the node architecture from this repository's
[releases](https://github.com/cloudsmith-labs/cloudsmith-kubernetes-credential-provider/releases),
verify it with `checksums.txt`, and place the binary in the directory configured
by `--image-credential-provider-bin-dir`.

```bash
sudo install -o root -g root -m 0755 \
  cloudsmith-kubernetes-credential-provider \
  /usr/local/bin/cloudsmith-kubernetes-credential-provider
```

Start kubelet with:

```text
--image-credential-provider-config=/etc/kubernetes/credential-provider-config.yaml
--image-credential-provider-bin-dir=/usr/local/bin
```

## Service account example

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cloudsmith-puller
  namespace: default
  annotations:
    cloudsmith.io/org-slug: example-org
    cloudsmith.io/service-slug: example-service
---
apiVersion: v1
kind: Pod
metadata:
  name: private-image
  namespace: default
spec:
  serviceAccountName: cloudsmith-puller
  containers:
    - name: app
      image: docker.cloudsmith.io/example-org/example-repo/app:latest
```

## Development

Install the pinned Go, Node.js, pnpm, pre-commit, golangci-lint, GoReleaser,
and zizmor versions with [mise](https://mise.jdx.dev/):

```bash
mise install
mise run ci
```

Run the complete package rather than the individual `main.go` file:

```bash
mise exec -- go run . version
mise exec -- go run . < request.json
```

Install the release automation dependencies with
`mise run pnpm-install`. CI providers only need to install mise and invoke
`mise run ci`; the GitHub workflows use the same individual tasks for parallel
job reporting.

CI renders zizmor findings as GitHub workflow annotations and fails the job
when findings are present. It does not require GitHub Advanced Security, SARIF
uploads, or `security-events` permissions.

## Protocol status

The provider is aligned with Kubernetes 1.37:

- KEP-4412 stage: beta
- Service account token feature: beta since Kubernetes 1.34
- Exec request and response API: `credentialprovider.kubelet.k8s.io/v1`
- Required kubelet beta config: `tokenAttributes.cacheType`
- Selected cache type: `Token`

See the [Kubernetes configuration guide](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/)
and [KEP metadata](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/4412-projected-service-account-tokens-for-kubelet-image-credential-providers/kep.yaml)
for the authoritative current status.
