package com.fooddelivery.apigateway.security.e2e;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Runtime gateway guard for exactly one test-harness endpoint while the explicitly enabled
 * {@code e2e} profile is active.
 *
 * <p>This class deliberately lives in main source because it must admit or deny live tunnel
 * traffic before the request is routed to IdentityService. It is not E2E test code. The following
 * {@code GlobalJwtAuthFilter} requires this server-side marker, so ordinary external traffic
 * cannot make the route public by merely sending a header.</p>
 */
@Component
@Profile("e2e")
@ConditionalOnProperty(prefix = "e2e.otp", name = "enabled", havingValue = "true")
public final class E2eOtpRunnerAccessFilter implements GlobalFilter, Ordered {

    public static final String OTP_LOOKUP_PATH = "/api/v1/internal/e2e/auth/otp";
    public static final String RUNNER_SECRET_HEADER = "X-E2E-Runner-Secret";
    public static final String VALIDATED_ATTRIBUTE =
            E2eOtpRunnerAccessFilter.class.getName() + ".validated";

    private final E2eRunnerSecretVerifier runnerSecretVerifier;

    public E2eOtpRunnerAccessFilter(@Value("${e2e.runner.secret:}") String runnerSecret) {
        runnerSecretVerifier = new E2eRunnerSecretVerifier(runnerSecret);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!isOtpLookupRequest(exchange)) {
            return chain.filter(exchange);
        }

        List<String> suppliedSecrets = exchange.getRequest().getHeaders().get(RUNNER_SECRET_HEADER);
        if (!runnerSecretVerifier.matches(suppliedSecrets)) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        exchange.getAttributes().put(VALIDATED_ATTRIBUTE, Boolean.TRUE);
        return chain.filter(exchange);
    }

    public static boolean isOtpLookupPath(String path) {
        return OTP_LOOKUP_PATH.equals(path);
    }

    static boolean isOtpLookupRequest(ServerWebExchange exchange) {
        return exchange.getRequest().getMethod() == HttpMethod.GET
                && isOtpLookupPath(exchange.getRequest().getURI().getPath());
    }

    public static boolean isValidated(ServerWebExchange exchange) {
        return Boolean.TRUE.equals(exchange.getAttribute(VALIDATED_ATTRIBUTE));
    }

    @Override
    public int getOrder() {
        return -2;
    }
}
