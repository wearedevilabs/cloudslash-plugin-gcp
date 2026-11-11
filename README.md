# CloudSlash GCP plugin

Read-only Google Cloud inventory for CloudSlash. It discovers Compute Engine
instances, disks, static addresses, forwarding rules, networks, subnetworks, and
Cloud Storage buckets, then emits normalized CRNs and relationships to the core.

## Permissions

The plugin only reads metadata. Grant a dedicated service account:

- `resourcemanager.projects.get`
- `compute.instances.list`
- `compute.disks.list`
- `compute.addresses.list`
- `compute.forwardingRules.list`
- `compute.networks.list`
- `compute.subnetworks.list`
- `storage.buckets.list`

The built-in `Viewer` and `Storage Object Viewer` roles cover these. Do not grant
write or admin roles.

## Connect

1. Create a service account in the target project.
2. Grant it the read-only permissions above.
3. Create a JSON key.
4. Add a GCP connection in CloudSlash with the project ID and the JSON key, or
   run `cs plugin host gcp --run` and use the hosted connection form.

The service account key is stored as a write-only secret by the connection
layer. The plugin never uses ambient Google credentials.

## Run locally

```sh
go build -o gcp-plugin .
```

The local provider is read-only and exposes no remediation actions.

## Hosted

`cs plugin host gcp --run` builds `cmd/hosted`, which serves the v3 source over
native gRPC and gRPC-Web. The CloudSlash CLI isolates the quick tunnel and
forces HTTP/2 so the transport works without a Cloudflare account. See
`docs-site/docs/explanation/grpc-web-hosted-plugins.md`.
