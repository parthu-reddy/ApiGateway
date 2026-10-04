package com.fooddelivery.apigateway.security;

import com.fooddelivery.common.security.IdentityTokenService;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;

class ActuatorAccessFilterTest {
    private final IdentityTokenService signatures = new IdentityTokenService("private-local-fixture-only-operator-signing-key", null);
    private final ActuatorAccessFilter filter = new ActuatorAccessFilter(signatures);
    private boolean admits(MockServerHttpRequest request) {
        var exchange = MockServerWebExchange.from(request); var calls = new AtomicInteger();
        filter.filter(exchange, next -> { calls.incrementAndGet(); return Mono.empty(); }).block();
        if (calls.get() == 0) assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        return calls.get() == 1;
    }
    private MockServerHttpRequest signed(String roles, long issued, boolean forged) {
        return MockServerHttpRequest.get("/actuator/prometheus").header("X-User-Id", "operator")
                .header("X-User-Roles", roles).header("X-Issued-At", Long.toString(issued))
                .header("X-Identity-Signature", forged ? "forged" : signatures.sign("operator", roles, null, null, issued)).build();
    }
    @Test void healthRemainsAvailableAndProductRequestsKeepTheirExistingChain() {
        assertTrue(admits(MockServerHttpRequest.get("/actuator/health/readiness").build()));
        assertTrue(admits(MockServerHttpRequest.head("/actuator/health").build()));
        assertTrue(admits(MockServerHttpRequest.head("/actuator/health/readiness").build()));
        assertFalse(admits(MockServerHttpRequest.post("/actuator/health").build()));
        assertFalse(admits(MockServerHttpRequest.head("/actuator/prometheus").build()));
        assertTrue(admits(MockServerHttpRequest.get("/api/v1/users/me/portals").build()));
    }
    @Test void unsignedOrForgedHeadersCannotReadOperatorTelemetry() {
        assertFalse(admits(MockServerHttpRequest.get("/actuator/prometheus").build()));
        assertFalse(admits(signed("SERVICE", System.currentTimeMillis(), true)));
        assertFalse(admits(signed("ADMIN", System.currentTimeMillis(), false)));
    }
    @Test void freshSignedServiceReadIsAcceptedButOldOrFutureSignaturesAreRefused() {
        long now = System.currentTimeMillis();
        assertTrue(admits(signed("SERVICE", now, false)));
        assertFalse(admits(signed("SERVICE", now - 600_000, false)));
        assertFalse(admits(signed("SERVICE", now + 600_000, false)));
    }
    @Test void missingTimestampAndActuatorMutationsFailClosed() {
        assertFalse(admits(MockServerHttpRequest.get("/actuator/metrics").header("X-User-Id", "operator")
                .header("X-User-Roles", "SERVICE").build()));
        assertFalse(admits(MockServerHttpRequest.post("/actuator/gateway/refresh").build()));
    }
}
