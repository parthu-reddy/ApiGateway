package com.fooddelivery.apigateway.security;

import java.net.InetSocketAddress;

import org.springframework.boot.web.reactive.context.ReactiveWebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * Actuator is not a Gateway route, and this filter runs on both of the gateway's ports (GatewayScrapeAndAlerting
 * Phase 1 spike S-1), so it decides by the port a request arrived on.
 *
 * <ul>
 *   <li>The management port ({@code management.server.port}, never published by compose) serves actuator reads to
 *       anyone on the compose network, like every internal service: Prometheus scrapes it anonymously. Only GET and
 *       HEAD pass, so Spring Cloud Gateway's route writes ({@code POST /actuator/gateway/refresh}, route
 *       create/delete) can never be reached.
 *   <li>Every other port — the public edge — answers 404 for {@code /actuator/**}. If the management port setting is
 *       ever removed there is no management server, every actuator request lands here, and the scrape fails rather
 *       than the edge opening.
 * </ul>
 */
@Component
public final class ActuatorAccessFilter
        implements WebFilter, Ordered, ApplicationListener<ReactiveWebServerInitializedEvent> {

    /** The management server's bound port; -1 until it starts (or when it shares the main server). */
    private volatile int managementPort = -1;

    @Override
    public void onApplicationEvent(ReactiveWebServerInitializedEvent event) {
        if ("management".equals(event.getApplicationContext().getServerNamespace()))
            managementPort = event.getWebServer().getPort();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!path.equals("/actuator") && !path.startsWith("/actuator/"))
            return chain.filter(exchange);
        InetSocketAddress local = exchange.getRequest().getLocalAddress();
        if (local == null || managementPort <= 0 || local.getPort() != managementPort)
            return refuse(exchange, HttpStatus.NOT_FOUND);
        HttpMethod method = exchange.getRequest().getMethod();
        if (method == HttpMethod.GET || method == HttpMethod.HEAD)
            return chain.filter(exchange);
        return refuse(exchange, HttpStatus.METHOD_NOT_ALLOWED);
    }

    private static Mono<Void> refuse(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}
