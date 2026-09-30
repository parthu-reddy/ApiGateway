package com.fooddelivery.apigateway.security.dev;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Admits only the Dev Autofill Code route when enabled in Dev and never alongside prod.
 * IdentityService independently restricts the requested account and portal to its seeded policy.
 * The following JWT filter requires this server-owned attribute before routing the lookup.
 */
@Component
@Profile("dev & !prod")
@ConditionalOnProperty(prefix = "dev.otp", name = "enabled", havingValue = "true")
public final class DevOtpAccessFilter implements GlobalFilter, Ordered {

    public static final String OTP_LOOKUP_PATH = "/api/v1/internal/auth/admin/otp";
    private static final String VALIDATED_ATTRIBUTE = DevOtpAccessFilter.class.getName() + ".validated";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (exchange.getRequest().getMethod() == HttpMethod.GET
                && isOtpLookupPath(exchange.getRequest().getURI().getPath())) {
            exchange.getAttributes().put(VALIDATED_ATTRIBUTE, Boolean.TRUE);
        }
        return chain.filter(exchange);
    }

    public static boolean isOtpLookupPath(String path) {
        return OTP_LOOKUP_PATH.equals(path);
    }

    public static boolean isValidated(ServerWebExchange exchange) {
        return Boolean.TRUE.equals(exchange.getAttribute(VALIDATED_ATTRIBUTE));
    }

    @Override
    public int getOrder() {
        return -2;
    }
}
