package com.fooddelivery.apigateway.security.e2e;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

class E2eOtpRunnerAccessFilterTest {

    private final E2eOtpRunnerAccessFilter filter = new E2eOtpRunnerAccessFilter("runner-secret");
    private final AtomicInteger passedToChain = new AtomicInteger();

    @Test
    void gatewayRefusesAnE2eProfileWithoutAConfiguredRunnerSecret() {
        assertThrows(IllegalStateException.class, () -> new E2eOtpRunnerAccessFilter(" "));
    }

    @Test
    void gatewayRejectsAnAbsentRunnerSecret() {
        MockServerWebExchange exchange = exchange(null);

        filter.filter(exchange, this::passThrough).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        assertEquals(0, passedToChain.get());
    }

    @Test
    void gatewayRejectsAnIncorrectRunnerSecret() {
        MockServerWebExchange exchange = exchange("wrong-secret");

        filter.filter(exchange, this::passThrough).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        assertEquals(0, passedToChain.get());
    }

    @Test
    void gatewayRejectsDuplicatedRunnerSecretHeaders() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .get(E2eOtpRunnerAccessFilter.OTP_LOOKUP_PATH)
                .header(E2eOtpRunnerAccessFilter.RUNNER_SECRET_HEADER, "runner-secret", "runner-secret")
                .build());

        filter.filter(exchange, this::passThrough).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        assertEquals(0, passedToChain.get());
    }

    @Test
    void gatewayMarksOnlyAValidRunnerRequestForTheJwtFilter() {
        MockServerWebExchange exchange = exchange("runner-secret");

        filter.filter(exchange, this::passThrough).block();

        assertEquals(1, passedToChain.get());
        assertEquals(Boolean.TRUE, exchange.getAttribute(E2eOtpRunnerAccessFilter.VALIDATED_ATTRIBUTE));
    }

    private Mono<Void> passThrough(org.springframework.web.server.ServerWebExchange ignored) {
        passedToChain.incrementAndGet();
        return Mono.empty();
    }

    private MockServerWebExchange exchange(String runnerSecret) {
        MockServerHttpRequest.BaseBuilder<?> request =
                MockServerHttpRequest.get(E2eOtpRunnerAccessFilter.OTP_LOOKUP_PATH);
        if (runnerSecret != null) {
            request.header(E2eOtpRunnerAccessFilter.RUNNER_SECRET_HEADER, runnerSecret);
        }
        return MockServerWebExchange.from(request.build());
    }
}
