# ApiGateway Service

The ApiGateway is the single entry point for all external client requests into the Food Delivery ecosystem. It handles route routing, load balancing, and global security enforcement (authentication and header propagation).

## Setup & Run
1. Ensure Java 17 and Maven are installed.
2. Run `mvn clean install` to build the service.
3. Start the application: `mvn spring-boot:run`
4. The service runs on port `8080`.

## Key Responsibilities
- **Routing**: Distributes incoming requests to `CustomerApplication`, `RestaurantApplication`, `DeliveryExecutiveApplication`, and `IdentityService`.
- **Authentication**: Validates incoming JWT tokens using `GlobalJwtAuthFilter`.
- **Context Propagation**: Strips raw JWTs and injects `X-User-Id`, `X-User-Roles`, and `X-User-Phone` headers into downstream requests.
- **Security**: Blocks external access to internal APIs (e.g., paths matching `/api/*/internal/**`).


<!-- dummy data -->
