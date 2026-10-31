package com.fooddelivery.apigateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetSocketAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The anonymous routes' rate-limit key, against the trusted proxies the deployment declares (Deployment/api-gateway.yml).
 * The Dev VM has two ways in: 8080 published straight to the internet, whose peer is the caller (Docker DNATs published
 * ports and keeps the source), and the UI's nginx on 80, which proxies /api/ to api-gateway:8080 over the compose
 * network and appends its own peer to X-Forwarded-For (FoodDeliveryAppUI/nginx.conf). RedisRateLimiter keys the bucket
 * by the resolved value alone (isAllowed(routeId, id) -> getKeys(id)), so the value is the bucket.
 */
class IpKeyResolverTest {

    private static final String CALLER = "198.51.100.7";
    private static final String UI_PROXY = "172.18.0.12";

    private final KeyResolver resolver = new RateLimiterConfig(trustedProxies()).ipKeyResolver();

    @Test
    void aDirectCallerCannotPickTheBucketWithForwardedFor() {
        String plain = key(direct(), "order-service");
        String spoofed = key(direct("203.0.113.1"), "order-service");
        String respoofed = key(direct("203.0.113.2, 10.0.0.1"), "order-service");
        assertEquals(plain, spoofed, "a caller on 8080 wrote X-Forwarded-For and moved to another bucket");
        assertEquals(plain, respoofed, "a caller on 8080 wrote X-Forwarded-For and moved to another bucket");
        assertEquals("order-service|ip:" + CALLER, plain);
    }

    @Test
    void behindTheUiProxyOnlyTheHopTheProxyAddedCounts() {
        assertEquals("order-service|ip:" + CALLER, key(proxied("203.0.113.1, " + CALLER), "order-service"));
        assertEquals("order-service|ip:" + CALLER, key(proxied("203.0.113.2, 10.0.0.1, " + CALLER), "order-service"));
        assertEquals("order-service|ip:" + CALLER, key(proxied("203.0.113.3", CALLER), "order-service"),
                "two header lines: the proxy's hop is still the last");
        assertNotEquals(key(proxied(CALLER), "order-service"), key(proxied("198.51.100.8"), "order-service"),
                "two callers behind the proxy must not share the proxy's bucket");
    }

    @Test
    void aProxiedRequestWithoutForwardedForIsKeyedByItsPeer() {
        assertEquals("order-service|ip:" + UI_PROXY, key(proxied(), "order-service"));
        assertEquals("order-service|ip:" + UI_PROXY, key(proxied(""), "order-service"));
    }

    @Test
    void twoRoutesDoNotShareABucket() {
        String orders = key(direct(), "order-service");
        String customers = key(direct(), "customer-service");
        assertEquals("customer-service|ip:" + CALLER, customers);
        assertNotEquals(orders, customers, "RedisRateLimiter keys by this value alone: one value would be one bucket");
        assertNotEquals(key(proxied(CALLER), "order-service"), key(proxied(CALLER), "customer-service"));
    }

    private static List<String> trustedProxies() {
        try {
            List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                    .load("api-gateway.yml", new FileSystemResource("../Deployment/api-gateway.yml"));
            return new Binder(ConfigurationPropertySources.from(sources))
                    .bind("gateway.rate-limit.trusted-proxies", Bindable.listOf(String.class)).get();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static MockServerHttpRequest direct(String... forwardedFor) {
        return request(CALLER, forwardedFor);
    }

    private static MockServerHttpRequest proxied(String... forwardedFor) {
        return request(UI_PROXY, forwardedFor);
    }

    private static MockServerHttpRequest request(String peer, String... forwardedFor) {
        MockServerHttpRequest.BaseBuilder<?> builder = MockServerHttpRequest.get("/api/v1/orders/mine")
                .remoteAddress(new InetSocketAddress(peer, 4000));
        if (forwardedFor.length > 0) {
            builder.header("X-Forwarded-For", forwardedFor);
        }
        return builder.build();
    }

    private String key(MockServerHttpRequest request, String routeId) {
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR,
                Route.async().id(routeId).uri("lb://" + routeId).predicate(e -> true).build());
        return resolver.resolve(exchange).block();
    }
}
