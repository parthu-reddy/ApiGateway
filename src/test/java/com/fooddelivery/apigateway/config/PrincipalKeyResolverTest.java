package com.fooddelivery.apigateway.config;

import com.fooddelivery.apigateway.filter.GlobalJwtAuthFilter;
import com.fooddelivery.common.security.IdentityTokenService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.ReactiveValueOperations;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The dining routes' rate-limit key (waiter plan D23, S43): the verified principal per route. The spoofing case runs the
 * real GlobalJwtAuthFilter first and keys the exchange it hands on, as the gateway does (global filter at order -1, then
 * the route's RequestRateLimiter).
 */
class PrincipalKeyResolverTest {

    private static final String USER = "11111111-1111-1111-1111-111111111111";
    private static final String SID = "owned-session";
    private static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");
    private static KeyPair keys;

    private final KeyResolver resolver = new RateLimiterConfig(List.of("172.16.0.0/12")).principalKeyResolver();
    private final ReactiveStringRedisTemplate redis = mock(ReactiveStringRedisTemplate.class);
    private final ReactiveValueOperations<String, String> values = mock(ReactiveValueOperations.class);
    private final IdentityTokenService identity = mock(IdentityTokenService.class);
    private GlobalJwtAuthFilter filter;

    @BeforeAll
    static void rsa() throws Exception {
        keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    @BeforeEach
    void setup() {
        filter = new GlobalJwtAuthFilter();
        String pem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(keys.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----";
        ReflectionTestUtils.setField(filter, "publicKeyResource", new ByteArrayResource(pem.getBytes(StandardCharsets.UTF_8)));
        ReflectionTestUtils.setField(filter, "redisTemplate", redis);
        ReflectionTestUtils.setField(filter, "identityTokenService", identity);
        ReflectionTestUtils.setField(filter, "metrics", new SimpleMeterRegistry());
        RbacConfig rules = new RbacConfig();
        rules.setRules(Map.of("kitchen", List.of("/api/v1/dining")));
        ReflectionTestUtils.setField(filter, "rbacConfig", rules);
        when(redis.opsForValue()).thenReturn(values);
        when(identity.sign(any(), any(), any(), any(), anyLong())).thenReturn("verified-signature");
        filter.init();
        ReflectionTestUtils.setField(filter, "jwtParser", Jwts.parserBuilder().setSigningKey(keys.getPublic())
                .setClock(() -> Date.from(NOW)).build());
        String session = "[{\"sessionId\":\"" + SID + "\",\"purpose\":\"LOGIN\",\"absoluteExpiresAt\":\"2026-11-02T12:00:00Z\"}]";
        when(values.multiGet(List.of("BLACKLIST:SESSION:" + SID, "ENTITLEMENTS_VERSION:" + USER, "USER_SESSIONS:" + USER)))
                .thenReturn(Mono.just(Arrays.asList(null, "1", session)));
    }

    @Test
    void theGatewaysUserIdKeysTheBucketPerRoute() {
        String dining = key(onRoute(MockServerWebExchange.from(signedIn()), "restaurant-dining"));
        String guest = key(onRoute(MockServerWebExchange.from(signedIn()), "restaurant-dining-guest"));
        assertEquals("restaurant-dining|user:" + USER, dining);
        assertEquals("restaurant-dining-guest|user:" + USER, guest);
        assertNotEquals(dining, guest, "RedisRateLimiter keys by this value alone: one value would be one bucket");
    }

    @Test
    void aClientSentUserIdCannotPickTheBucket() {
        MockServerHttpRequest spoofed = MockServerHttpRequest.post("/api/v1/dining/outlets/o/sessions")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token())
                .header("X-User-Id", "22222222-2222-2222-2222-222222222222")
                .remoteAddress(new InetSocketAddress("10.0.0.7", 4000)).build();
        ServerWebExchange forwarded = throughTheAuthFilter(MockServerWebExchange.from(spoofed));
        assertEquals("restaurant-dining-guest|user:" + USER, key(onRoute(forwarded, "restaurant-dining-guest")));

        MockServerHttpRequest anonymous = MockServerHttpRequest.get("/api/v1/brands")
                .header("X-User-Id", "22222222-2222-2222-2222-222222222222")
                .remoteAddress(new InetSocketAddress("10.0.0.8", 4000)).build();
        ServerWebExchange stripped = throughTheAuthFilter(MockServerWebExchange.from(anonymous));
        assertEquals("restaurant-dining|anon:10.0.0.8", key(onRoute(stripped, "restaurant-dining")));
    }

    @Test
    void anAnonymousCallerIsKeyedByRemoteAddressNotForwardedFor() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/v1/dining/me/workplace")
                .header("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
                .remoteAddress(new InetSocketAddress("10.0.0.9", 4000)).build();
        assertEquals("restaurant-dining|anon:10.0.0.9", key(onRoute(MockServerWebExchange.from(request), "restaurant-dining")));
    }

    private MockServerHttpRequest signedIn() {
        return MockServerHttpRequest.get("/api/v1/dining/me/workplace").header("X-User-Id", USER)
                .remoteAddress(new InetSocketAddress("10.0.0.6", 4000)).build();
    }

    private ServerWebExchange throughTheAuthFilter(ServerWebExchange exchange) {
        AtomicReference<ServerWebExchange> next = new AtomicReference<>();
        filter.filter(exchange, e -> {
            next.set(e);
            return Mono.empty();
        }).block();
        assertNotNull(next.get(), "the auth filter refused the request: " + exchange.getResponse().getStatusCode());
        return next.get();
    }

    private static ServerWebExchange onRoute(ServerWebExchange exchange, String routeId) {
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR,
                Route.async().id(routeId).uri("lb://restaurant-service").predicate(e -> true).build());
        return exchange;
    }

    private String key(ServerWebExchange exchange) {
        return resolver.resolve(exchange).block();
    }

    private static String token() {
        return Jwts.builder().setSubject(USER).claim("roles", List.of("KITCHEN")).claim("sessionId", SID).claim("ev", 1)
                .setIssuedAt(Date.from(NOW.minusSeconds(60))).setExpiration(Date.from(NOW.plusSeconds(600)))
                .signWith(keys.getPrivate(), SignatureAlgorithm.RS256).compact();
    }
}
