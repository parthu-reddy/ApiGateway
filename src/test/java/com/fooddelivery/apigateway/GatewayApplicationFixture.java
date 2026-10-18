package com.fooddelivery.apigateway;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

/**
 * Complete gateway wiring, isolated discovery and mocked cache; no infrastructure fixture. The routes and RBAC rules
 * are ConfigService's own file (Deployment/api-gateway.yml, the sibling checkout CI provides): the gateway packages
 * none, so a test can only exercise the configuration production runs.
 */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
    "spring.config.import=file:../Deployment/api-gateway.yml",
    // The deployment supplies this from OCI Vault; the Ola Maps route's AddRequestParameter rejects an empty value.
    "OLA_MAPS_API_KEY=test-ola-maps-key",
    "spring.cloud.config.enabled=false","spring.cloud.discovery.enabled=false","eureka.client.enabled=false",
    "management.health.redis.enabled=false",
    // The imported file puts the actuator on 9080; a fixed port collides across cached test contexts.
    "management.server.port=0"})
abstract class GatewayApplicationFixture {
    @MockBean ReactiveRedisConnectionFactory cacheConnection;
    @MockBean org.springframework.data.redis.connection.RedisConnectionFactory synchronousCacheConnection;
    @MockBean ReactiveStringRedisTemplate cache;
}
