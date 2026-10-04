package com.fooddelivery.apigateway;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

/** Complete gateway wiring, isolated discovery and mocked cache; no infrastructure fixture. */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
    "spring.cloud.config.enabled=false","spring.cloud.discovery.enabled=false","eureka.client.enabled=false",
    "management.health.redis.enabled=false"})
abstract class GatewayApplicationFixture {
    @MockBean ReactiveRedisConnectionFactory cacheConnection;
    @MockBean org.springframework.data.redis.connection.RedisConnectionFactory synchronousCacheConnection;
    @MockBean ReactiveStringRedisTemplate cache;
}
