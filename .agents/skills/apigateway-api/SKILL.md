---
name: apigateway-api
description: Complete API reference and integration guide for the ApiGateway. Use this to understand how external requests are routed and authenticated before reaching downstream services.
---

# ApiGateway API Reference

The ApiGateway does not expose functional REST APIs itself, but rather acts as a reverse proxy for downstream services. 

## Base URL
Default local environment: `http://localhost:8080`

## Routing Rules
- `/api/v1/auth/**` -> Routes to `IdentityService`
- `/api/customer/**` -> Routes to `CustomerApplication`
- `/api/restaurant/**` -> Routes to `RestaurantApplication`
- `/api/delivery/**` -> Routes to `DeliveryExecutiveApplication`
- `/api/v1/internal/**` -> Blocked from external access (Returns 403 Forbidden).

## Authentication
All endpoints (except public ones like `/api/v1/auth/send-otp` and `/api/v1/auth/verify-otp`) require a valid JWT token in the `Authorization: Bearer <token>` header.

The Gateway extracts the claims from the JWT and injects the following headers into downstream requests:
- `X-User-Id`: The user's UUID
- `X-User-Roles`: A comma-separated list of the user's roles
- `X-User-Phone`: The user's phone number
