package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.config.MapsGatewayProperties;
import com.fooddelivery.apigateway.security.MapsRoutes;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;

/** Maps release-set and layer-catalogue administration routes (MapsService internal/edge/releases.go). */
class MapsReleaseAdminRoutesTest {
    static final String HASH = "a".repeat(64);
    static final String ID = "11111111-1111-4111-8111-111111111111";
    static final Set<HttpMethod> POST = Set.of(HttpMethod.POST);
    static final Set<HttpMethod> GET = Set.of(HttpMethod.GET);
    static final Set<HttpMethod> BOTH = Set.of(HttpMethod.GET, HttpMethod.POST);
    static final java.util.function.Function<org.springframework.http.server.reactive.ServerHttpRequest,String> PEER =
            r -> r.getRemoteAddress() == null ? "unknown" : r.getRemoteAddress().getAddress().getHostAddress();

    // Every edge route of HandlerWithReleaseAdmin, with its methods and body envelope.
    static final Map<String, Set<HttpMethod>> PRIVATE = Map.of(
            "/api/v1/releases/candidates", POST,
            "/api/v1/releases/candidates/" + HASH + "/review", POST,
            "/api/v1/releases/active", POST,
            "/api/v1/catalogue/candidates", BOTH,
            "/api/v1/catalogue/candidates/" + ID, GET,
            "/api/v1/catalogue/candidates/" + ID + "/jobs", BOTH,
            "/api/v1/catalogue/candidates/" + ID + "/jobs/" + ID + "/steps", POST,
            "/api/v1/catalogue/candidates/" + ID + "/jobs/" + ID + "/reviews", POST,
            "/api/v1/catalogue/candidates/" + ID + "/review", POST,
            "/api/v1/catalogue/active", POST);

    MapsGatewayProperties configured() {
        var p = new MapsGatewayProperties(); p.setEnabled(true); p.setClientKeySecret("ab".repeat(32)); return p;
    }
    MockServerWebExchange exchange(MockServerHttpRequest request) {
        var e = MockServerWebExchange.from(request);
        var policy = MapsRoutes.classify(request.getURI().getPath());
        if (policy != null) e.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR,
                Route.async().id("maps-v1-" + policy.backend()).uri("https://internal.test")
                        .predicate(x -> true).metadata("maps.contract", "v1").metadata("maps.backend", policy.backend()).build());
        return e;
    }

    @Test void everyAdministrationRouteIsPrivateOnTheEdgeWithExactMethods() {
        for (String alias : List.of("", "/maps-service")) {
            for (var entry : PRIVATE.entrySet()) {
                var policy = MapsRoutes.classify(alias + entry.getKey());
                assertNotNull(policy, entry.getKey());
                assertEquals("edge", policy.backend(), entry.getKey());
                assertFalse(policy.publicRoute(), entry.getKey());
                assertEquals(entry.getValue(), policy.methods(), entry.getKey());
            }
            var catalogue = MapsRoutes.classify(alias + "/api/v1/catalogue");
            assertEquals("edge", catalogue.backend());
            assertTrue(catalogue.publicRoute());
            assertEquals(GET, catalogue.methods());
            assertEquals(GET, MapsRoutes.classify(alias + "/api/v1/catalogue/reviews").methods());
        }
    }

    @Test void variantPathsStayClosed() {
        for (String refused : List.of("/api/v1/releases", "/api/v1/releases/candidates/" + HASH,
                "/api/v1/releases/candidates/" + HASH.toUpperCase() + "/review", "/api/v1/releases/candidates/" + HASH + "/review/extra",
                "/api/v1/releases/candidates/..%2F" + HASH + "/review", "/api/v1/releases/candidates/" + HASH + "%2Freview",
                "/api/v1/releases/active/extra", "/api/v1/releases/current", "/api/v1/catalogue/", "/api/v1/catalogue/candidates/not-an-id",
                "/api/v1/catalogue/candidates/" + ID + "/jobs/" + ID, "/api/v1/catalogue/candidates/" + ID + "/jobs/" + ID + "/complete",
                "/api/v1/catalogue/candidates/" + ID + "/publish", "/api/v1/catalogue/active/" + ID, "/api/v1/catalogue/jobs")) {
            assertNull(MapsRoutes.classify(refused), refused);
            assertNull(MapsRoutes.classify("/maps-service" + refused), refused);
        }
    }

    @Test void manifestAndBundleBodiesUseTheEdgeDecoderLimitOthersTheDefault() {
        var buffers = DefaultDataBufferFactory.sharedInstance;
        for (var item : Map.of("/api/v1/releases/candidates", 32_768, "/api/v1/catalogue/candidates", 32_768,
                "/api/v1/releases/active", 8192, "/api/v1/catalogue/candidates/" + ID + "/review", 8192).entrySet()) {
            for (int size : new int[]{item.getValue(), item.getValue() + 1}) {
                var request = exchange(MockServerHttpRequest.post(item.getKey()).header(HttpHeaders.TRANSFER_ENCODING, "chunked")
                        .body(Flux.just(buffers.wrap(new byte[size]))));
                var received = new AtomicInteger();
                new MapsGatewayFilter(configured(), PEER).filter(request, x -> DataBufferUtils.join(x.getRequest().getBody())
                        .doOnNext(b -> { received.set(b.readableByteCount()); DataBufferUtils.release(b); }).then()).block();
                if (size == item.getValue()) {
                    assertNull(request.getResponse().getStatusCode(), item.getKey());
                    assertEquals(size, received.get(), item.getKey());
                } else {
                    assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, request.getResponse().getStatusCode(), item.getKey());
                    assertEquals(0, received.get(), item.getKey());
                }
            }
        }
    }

    @Test void aBearerCredentialOrAWrongMethodNeverReachesTheEdge() {
        for (var request : new MockServerHttpRequest[]{
                MockServerHttpRequest.post("/api/v1/releases/active").header(HttpHeaders.AUTHORIZATION, "Bearer " + HASH).build(),
                MockServerHttpRequest.get("/api/v1/releases/active").build(),
                MockServerHttpRequest.put("/api/v1/catalogue/active").build(),
                MockServerHttpRequest.delete("/api/v1/catalogue/candidates/" + ID).build()}) {
            var e = exchange(request);
            new MapsGatewayFilter(configured(), PEER).filter(e, x -> { fail("refused administration request was forwarded"); return Mono.empty(); }).block();
            assertTrue(e.getResponse().getStatusCode().is4xxClientError(), request.getURI().toString());
        }
    }
}
