# Dedicated Maps ingress v1

The opt-in `maps` profile adds exact source-backed policies through `MapsRoutes`
and `MapsGatewayFilter`, ahead of legacy JWT, signed-header and OPTIONS shortcuts.
Its enabled instance refuses undeclared routes, including ordinary identity/admin,
machine, engine and independent bearer paths. Default Food Delivery behavior and
its Config Server-owned routes retain independent regression coverage.

Configure HTTPS edge/public/assets/postal/routing backends, an explicit client
keystore and trust roots. Insecure upstream trust is refused. The Go edge verifies
the gateway's exact authorized URI SAN independently. Operator network ACLs and
external public TLS/origin remain required. Review the final effective packaged
configuration: Config Server precedence must not silently change these settings.

Private browser routes use only the Go opaque Cookie/CSRF flow; mixed Authorization
is refused. Public routes strip incidental credentials without calling optional
session authority. Incoming identity/mesh/forwarded/correlation fields are stripped.
URL credentials and ambiguous encoded paths are refused, with one exact declared
glyph-fontstack encoding exception. Range/If-Range/conditional/compression
negotiation is preserved; private routes cannot inherit credentialed public CORS.

Admission uses separate non-evictable public/private totals. The configured total
is partitioned by maximum simultaneously running replicas, including rolling
surge. Deployment must enforce that ceiling; this is not a distributed rated-load
claim. Bodies are bounded while streaming, slow uploads have a finite deadline,
and no domain mutation retry is introduced. Read routes refuse bodies. Private
responses are no-store. Maps actor quotas remain the Go/database owner's job.

Route declaration is not product domain activation. The default Maps edge does
not mount every private resource/editor adapter, and candidate-only source
validation cannot be treated as production admission. Privileged/client/recovery,
full composed public asset/body semantics, original product/load and independent
operator gates remain open. See
[the selected contract and complete handoff](https://github.com/parthu-reddy/RandomDocuments/pull/6)
and [IdentityService #2](https://github.com/parthu-reddy/IdentityService/pull/2).

Tests exercise the actual Maps + legacy GlobalJwt filter chain, preservation of
public transport headers, private OPTIONS/mixed/URL/header denial, canonical
alias/population replica partitioning and streaming overflow/timeout. The default
complete gateway suite also covers its unchanged routes, authorization and startup.
