package com.fooddelivery.apigateway.security;

import com.fooddelivery.common.security.IdentityTokenService;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/** Actuator is not a Gateway route: protect its operator reads before handler dispatch. */
@Component
public final class ActuatorAccessFilter implements WebFilter, Ordered {
    private final IdentityTokenService signatures;
    public ActuatorAccessFilter(IdentityTokenService signatures) { this.signatures = signatures; }

    @Override public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!path.equals("/actuator") && !path.startsWith("/actuator/")) return chain.filter(exchange);
        if (exchange.getRequest().getMethod() == HttpMethod.GET
                && (path.equals("/actuator/health") || path.startsWith("/actuator/health/"))) return chain.filter(exchange);
        if (exchange.getRequest().getMethod() == HttpMethod.GET && signedOperator(exchange)) return chain.filter(exchange);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private boolean signedOperator(ServerWebExchange exchange) {
        var headers = exchange.getRequest().getHeaders();
        String user = headers.getFirst("X-User-Id"), roles = headers.getFirst("X-User-Roles");
        if (user == null || user.isBlank() || !"SERVICE".equals(roles)) return false;
        try {
            long issued = Long.parseLong(headers.getFirst("X-Issued-At"));
            long now = System.currentTimeMillis();
            if (issued < now - 300_000 || issued > now + 30_000) return false;
            return signatures.verify(headers.getFirst("X-Identity-Signature"), user, roles,
                    headers.getFirst("X-User-Phone"), headers.getFirst("X-Session-Id"), issued);
        } catch (RuntimeException invalid) { return false; }
    }

    @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 10; }
}
