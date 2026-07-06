---
name: understand-apigateway
description: Comprehensive architectural overview and troubleshooting guide for the ApiGateway. Use this skill to understand the global authentication filter and routing mechanism.
---

# Understand ApiGateway

The ApiGateway acts as the primary defense mechanism and router for the microservice ecosystem, built on Spring Cloud Gateway.

## Architecture

- **GlobalJwtAuthFilter**: A global filter applied to all routes. It extracts the JWT from the `Authorization: Bearer <token>` header, verifies the signature using the shared secret, and extracts the claims.
- **Header Propagation**: Crucially, the gateway prevents downstream services from needing to validate JWTs. It injects the `X-User-Id`, `X-User-Roles`, and `X-User-Phone` headers.
- **Internal API Protection**: The gateway routing configuration explicitly omits routes for internal service endpoints (e.g., `/api/v1/internal/**`). External requests cannot reach these endpoints, enforcing security by design.

## Troubleshooting

- **401 Unauthorized**: Ensure the `Authorization` header is correctly formatted and the JWT is not expired.
- **403 Forbidden**: If hitting an internal endpoint from the outside, this is expected behavior.
- **Missing Headers in Downstream**: Verify that `GlobalJwtAuthFilter` is actively stripping the `Authorization` header and injecting the `X-*` headers correctly via the mutated `ServerWebExchange`.
