package com.fooddelivery.apigateway.security;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.reactive.context.ReactiveWebServerApplicationContext;
import org.springframework.boot.web.reactive.context.ReactiveWebServerInitializedEvent;
import org.springframework.boot.web.server.WebServer;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ActuatorAccessFilterTest {
    private static final int EDGE = 8080, MANAGEMENT = 9080;
    private ActuatorAccessFilter filter;

    private static ReactiveWebServerInitializedEvent started(String namespace, int port) {
        var server = mock(WebServer.class); when(server.getPort()).thenReturn(port);
        var context = mock(ReactiveWebServerApplicationContext.class); when(context.getServerNamespace()).thenReturn(namespace);
        return new ReactiveWebServerInitializedEvent(server, context);
    }
    @BeforeEach void servers() {
        filter = new ActuatorAccessFilter();
        filter.onApplicationEvent(started(null, EDGE));
        filter.onApplicationEvent(started("management", MANAGEMENT));
    }
    /** The status the filter set, or null when it passed the request on. */
    private HttpStatus outcome(MockServerHttpRequest.BaseBuilder<?> request, int port) {
        var exchange = MockServerWebExchange.from(request.localAddress(new InetSocketAddress("127.0.0.1", port)));
        var calls = new AtomicInteger();
        filter.filter(exchange, next -> { calls.incrementAndGet(); return Mono.empty(); }).block();
        return calls.get() == 1 ? null : (HttpStatus) exchange.getResponse().getStatusCode();
    }
    @Test void productRequestsPassOnAnyPort() {
        assertNull(outcome(MockServerHttpRequest.get("/api/v1/users/me/portals"), EDGE));
        assertNull(outcome(MockServerHttpRequest.post("/api/v1/auth/logout"), EDGE));
        assertNull(outcome(MockServerHttpRequest.get("/actuatorish"), EDGE));
    }
    @Test void theEdgeAnswersNotFoundForEveryActuatorRequest() {
        for (var request : new MockServerHttpRequest.BaseBuilder<?>[] {MockServerHttpRequest.get("/actuator"),
                MockServerHttpRequest.get("/actuator/prometheus"), MockServerHttpRequest.head("/actuator/health"),
                MockServerHttpRequest.post("/actuator/gateway/refresh")})
            assertEquals(HttpStatus.NOT_FOUND, outcome(request, EDGE));
    }
    @Test void theManagementPortAdmitsAnonymousReadsOnly() {
        assertNull(outcome(MockServerHttpRequest.get("/actuator/prometheus"), MANAGEMENT));
        assertNull(outcome(MockServerHttpRequest.head("/actuator/health"), MANAGEMENT));
        assertNull(outcome(MockServerHttpRequest.get("/actuator/gateway/routes"), MANAGEMENT));
        assertEquals(HttpStatus.METHOD_NOT_ALLOWED, outcome(MockServerHttpRequest.post("/actuator/gateway/refresh"), MANAGEMENT));
        assertEquals(HttpStatus.METHOD_NOT_ALLOWED, outcome(MockServerHttpRequest.delete("/actuator/gateway/routes/r1"), MANAGEMENT));
    }
    @Test void withoutAManagementServerNoPortServesActuator() {
        filter = new ActuatorAccessFilter();
        filter.onApplicationEvent(started(null, EDGE));
        assertEquals(HttpStatus.NOT_FOUND, outcome(MockServerHttpRequest.get("/actuator/prometheus"), EDGE));
        assertEquals(HttpStatus.NOT_FOUND, outcome(MockServerHttpRequest.get("/actuator/prometheus"), MANAGEMENT));
    }
}
