# cert-manager-webhook-volcengine

A Go package and cert-manager DNS-01 webhook for Volcengine public DNS. It uses a fixed
allowlist of resolved DNS names and a dedicated Volcengine project, and records
ownership in a pre-existing Kubernetes ConfigMap. It does not manage issuers,
certificate lifecycles, CNAMEs, or other DNS records.

## Go package

The module path is `github.com/liamxujia/cert-manager-webhook-volcengine`.
The root package exposes a cert-manager `webhook.Solver`; the standalone
command and Helm chart use the same implementation. Configure your own API
group, allowed namespaces, exact DNS destinations, journal, and credential
file paths. For example:

```go
package main

import (
    "log"

    "github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
    volcengine "github.com/liamxujia/cert-manager-webhook-volcengine"
)

func main() {
    solver, err := volcengine.New(volcengine.Config{
        JournalNamespace: "cert-manager",
        JournalName: "volcengine-dns01-journal",
        AllowedNamespaces: []string{"cert-manager"},
        Targets: []volcengine.Target{{
            FQDN: "apps.acme.example.com.", Zone: "acme.example.com.",
            ZoneID: 123456, Project: "example-acme",
        }},
    }, volcengine.CredentialFiles{
        AccessKeyPath: "/credentials/access-key",
        SecretKeyPath: "/credentials/secret-key",
    })
    if err != nil {
        log.Fatal(err)
    }
    cmd.RunWebhookServer("acme.example.com", solver)
}
```

The journal must already exist and the service account must be able to read
and update it. The command also supports `NewFromEnvironment` through the
`GROUP_NAME`, `POD_NAMESPACE`, `JOURNAL_NAME`, `ALLOWED_NAMESPACES`,
`DNS_TARGETS_JSON`, `VOLCENGINE_ACCESS_KEY_FILE`, and
`VOLCENGINE_SECRET_KEY_FILE` environment variables. `GROUP_NAME` is used by
the command to register the webhook API group; the package constructor itself
does not register an API group.

Install the public module in a Go module with:

```sh
go get github.com/liamxujia/cert-manager-webhook-volcengine@latest
```

No stable version has been tagged yet; use a specific commit or the resolved
pseudo-version to pin a dependency.

## Safety properties

- Each resolved FQDN is mapped to one explicit zone, numeric zone ID and
  non-default Volcengine project. Only allowed cert-manager resource namespaces
  can request a challenge. Per-request provider configuration is rejected.
- The IAM identity needs `dns:ListRecords`, `dns:CreateRecord` and
  `dns:DeleteRecord` for the dedicated validation project and zones. It does
  not need `ListZones` or authority over the parent zones. Verify the effective
  provider-side permissions before deployment: webhook restrictions do not
  replace IAM.
- `Present` writes a `creating` journal entry before requesting creation and
  records the returned record ID before declaring success. A matching TXT
  value without an ownership entry is never adopted. Duplicate in-flight
  requests fail and can be retried by cert-manager.
- `CleanUp` only deletes the journal-owned record ID after checking its zone,
  host, type and value, and sends `ProjectName` with the delete request.
  Different TXT records at the same name are preserved. The provider API does
  not supply a compare-and-delete condition in this implementation, so the
  read and delete are not atomic with respect to other DNS administrators.
  Restrict other writers to the dedicated validation zones and investigate
  unexpected external changes. The whole dedicated zone is inspected so that
  a record moved to another host or type cannot be mistaken for a deletion;
  zones with over 500 records or incomplete inventories fail closed.
- An uncertain create, delete, or journal update is held for operator
  inspection. There is no automatic adoption, retry of an uncertain write, or
  deletion based solely on a matching TXT value. Do not delete, replace, copy
  between environments, or edit a journal while any operation is in flight.
  Back up the ConfigMap as operational state. For a held entry, determine the
  exact provider request outcome and record ownership before planning recovery;
  this repository does not yet provide an automated recovery command.
- Credentials are read from mounted files at startup, are not passed through
  Issuer configuration, and are not printed. Restart the deployment after
  rotating them. The process can read and update only its named journal
  ConfigMap through its application RBAC; Kubernetes aggregated API auth
  requires the standard authentication-reader and auth-delegator bindings.

## Requirements

- Kubernetes compatible with cert-manager v1.21.3, already installed.
- A separate deployment, immutable image, DNS identity, journal and target
  allowlist for each environment. The chart installs one webhook per cluster
  under an operator-selected API group, solver name `volcengine`.
- An existing Secret in the deployment namespace with file keys `access-key`
  and `secret-key`, containing a dedicated restricted identity. Provisioning
  or rotating those credentials is outside this repository.
- An existing mutable ConfigMap named `volcengine-dns01-journal` in the
  deployment namespace. Create it once before the first deployment and retain
  it across upgrades and restarts. The chart deliberately does not create or
  reset it.
- Explicit DNS-01 CNAME delegation to a validation zone when the validated
  name is not itself in that zone. In the cert-manager Issuer, set
  `dns01.cnameStrategy: Follow`. Confirm exact CNAMEs and authoritative
  propagation before issuing certificates.

The challenge value is restricted to a 43-character unpadded base64url
SHA-256 digest, as used for ACME DNS-01. Targets and namespaces are loaded at
startup; changing them requires a deployment restart. Keep existing targets in
the allowlist until all entries associated with them are cleared.

## Build and test

```sh
go test ./...
go test -race ./...
go vet ./...
HELM=/path/to/helm go test ./charts -count=1
KUBEBUILDER_ASSETS=/path/to/envtest/bin go test -tags=integration ./internal/solver -run TestRealAPIServerJournalConcurrentChallenges -count=1
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/volcengine-dns01 ./cmd/volcengine-dns01
```

Chart tests skip when Helm is absent and `HELM` is not supplied. The default
integration test uses fake credentials, a local HTTP server and a fake
Kubernetes client. The opt-in `integration` test starts a local Kubernetes
API server and etcd, and exercises concurrent journal updates through the real
API. Neither test accesses a real DNS account or an existing cluster. The
official cert-manager DNS provider conformance suite and an actual DNS-01
issuance have not yet been run.

## Chart inputs

`charts/volcengine-dns01` requires an operator-controlled `groupName`, an image
reference pinned by sha256 and a nonempty `targets` list. For example, provide a reviewed values file with:

```yaml
groupName: acme.example.com
image: registry.example/volcengine-dns01@sha256:REPLACE_WITH_IMAGE_DIGEST
credentialSecret: volcengine-dns-credentials
journalName: volcengine-dns01-journal
allowedNamespaces:
  - cert-manager
targets:
  - fqdn: apps.acme.staging.example.com.
    zone: acme.staging.example.com.
    zoneID: 123456
    project: example-staging-acme
```

This example is illustrative and cannot be deployed until the image digest,
zone identities, IAM scope, CNAME delegation and Secret are reviewed. Each
FQDN and zone must be lowercase, fully qualified and end in a dot. No wildcard
is allowed in the target allowlist. Configuring the webhook solver in an
Issuer requires the same `groupName` as the chart, `solverName: volcengine`,
and no solver-specific `config` fields.

The chart does not create the DNS credential Secret, journal, public Issuer or
any public certificate. Before deploying, validate its manifests, Kubernetes
RBAC, APIService readiness, provider access, test-CA issuance and cleanup in
an isolated or staging environment. Keep DNS writes, credential changes and
production deployment within their own authorization boundaries.

## License

Apache License 2.0. See [LICENSE](LICENSE).
