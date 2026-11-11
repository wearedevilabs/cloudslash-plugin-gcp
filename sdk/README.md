# CloudSlash Plugin SDK

The SDK is the contract between a plugin and CloudSlash core. It is small on
purpose: plugins collect observations, CloudSlash owns the graph, findings,
cost, carbon, policy, plans and execution.

Module: `github.com/DrSkyle/cloudslash-plugin-sdk`

## Packages

| Package | Purpose |
| :--- | :--- |
| `shared/v3` | Hosted/customer-runner source contract: capabilities, preflight, scan batches, stream validation, connection methods and digests. |
| `shared/proto` | gRPC messages used by the hosted transport. |
| `shared` | Legacy local go-plugin interfaces and helpers. |
| `manifest` | Distribution manifest types and validation for local/code plugins. |
| `shared/crn` | Canonical CRN construction and helpers. |

## Hosted source contract

A hosted or customer-runner source is an out-of-process Go binary using gRPC
over TLS. It must ship:

- `cmd/hosted` — the entrypoint built by `cs plugin host <source> --run`;
- a `--manifest` mode that prints one JSON document;
- a read-only `v3.Source` with `Capability`, `Preflight` and `Scan`;
- `ConnectionMethods()` describing the connection fields and permissions.

The `--manifest` document has:

```json
{
  "plugin_name": "cloudslash-plugin-example",
  "version": "2.0.1",
  "capabilities": ["read.inventory"],
  "v3_capabilities": { "read.inventory": { "...": "..." } },
  "connection_methods": [ { "...": "..." } ]
}
```

The capability must include `connection_schema_digest`, computed by
`v3.ConnectionMethodsDigest(methods)`. CloudSlash recomputes the same digest and
the manifest digest from name, version, endpoint and capabilities; both are
pinned at registration and preflight.

## Versions

The plugin manifest version is the source of truth. `cs plugin host` injects it
into the hosted entrypoint with `-X main.version=<version>`. Bump the manifest
when you release; the registry, self-hosted listing and connection all follow.
Never hardcode a hosted release version.

## Connection methods

Each method is data:

```go
v3.ConnectionMethod{
    ID: "provider-config",
    Title: "Provider access",
    Instructions: "Create a read-only credential in the provider.",
    Permissions: []string{"read:inventory"},
    ReadOnly: true,
    Fields: []v3.ConnectionField{
        {Key: "endpoint", Label: "Endpoint", Type: "text", Required: true, MaxLength: 512},
        {Key: "token", Label: "Token", Type: "secret", Required: true, MaxLength: 512},
    },
}
```

The customer can record a subset of permissions; the credential or role still
decides actual access. Mutation methods are rejected. Add, remove or replace
fields and permission names for your system; do not assume IAM, SSH, a database
URL, or any provider-specific flow.

## Setup pages

An optional method can declare:

```go
SetupURL:  "https://plugins.example.com/setup",
SetupMode: "return", // "return" or "console"
```

`return` means the setup page performs the provider work and returns a finished
connection. Horizon opens it with `cloudslash_state` and `cloudslash_return`;
the page returns `?cloudslash_setup=<base64url(JSON)>` or POSTs the same payload
to `/v1/connections/setup-plugin-callback` from provider automation such as a
CloudFormation custom resource. The customer only reviews and approves inside
the plugin page. `console` opens a provider console and keeps the reviewed
field form.

A `setup_url` may contain `CLOUDSLASH_STATE` and `CLOUDSLASH_RETURN` tokens.
Horizon substitutes them before opening the page; otherwise it appends
`cloudslash_state` and `cloudslash_return`. This lets the plugin send the
customer straight to a provider quick-create page.

The bundled AWS plugin's setup URL is a prefilled CloudFormation review page;
the template lives in the plugin's `setup/` directory, is published to S3
because CloudFormation requires an S3 `TemplateURL`, and creates the role and
callback Lambda in the **customer's AWS account**. The publisher's bucket only
hosts the public template. The scaffold emits a `setup/` directory with
commented provider examples. The same pattern works for GCP, Azure,
Kubernetes, PostgreSQL, Git, SaaS, bare metal, or an internal API: the plugin
author supplies the provider template, and the customer approves it in their
own environment.

## Scaffold

`cs plugin create NAME --lang go` and Plugin Studio generate the current hosted
template: `main.go`, `cmd/hosted/main.go`, `internal/hosted/hosted.go`,
`source/source.go`, tests and a README. The connection methods and setup-mode
examples are commented so authors can add, remove or replace them.

See `docs-site/docs/how-to/building-plugins.md` and
`docs-site/docs/how-to/self-host-plugins.md`.
