package com.fooddelivery.apigateway.config;

import io.netty.handler.ipfilter.IpFilterRuleType;
import io.netty.handler.ipfilter.IpSubnetFilterRule;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.List;

@Configuration
public class RateLimiterConfig {

    private final List<IpSubnetFilterRule> trustedProxies;

    public RateLimiterConfig(@Value("${gateway.rate-limit.trusted-proxies}") List<String> trustedProxies) {
        this.trustedProxies = trustedProxies.stream().map(RateLimiterConfig::subnet).toList();
    }

    /**
     * One bucket per client address per route. The route id is part of the key for the reason principalKeyResolver gives.
     * The address is the socket's peer, unless that peer is a trusted proxy (gateway.rate-limit.trusted-proxies: the UI's
     * nginx), in which case it is the last X-Forwarded-For hop, the one that proxy appended. Earlier hops, and any
     * X-Forwarded-For sent by a caller reaching 8080 directly, are the client's own text and never pick the bucket.
     * Primary: RequestRateLimiterGatewayFilterFactory takes exactly one KeyResolver as its default (a route naming none);
     * with principalKeyResolver beside it the gateway fails to start without this.
     */
    @Bean
    @Primary
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            String routeId = route != null ? route.getId() : "no-route";
            return Mono.just(routeId + "|ip:" + clientAddress(exchange.getRequest()));
        };
    }

    /**
     * One bucket per signed-in person per route (waiter plan D23). X-User-Id is the gateway's own: GlobalJwtAuthFilter
     * (order -1) removes the client's header and sets the verified one before any route filter runs. Without it the
     * caller is keyed by the socket's remote address, never X-Forwarded-For, which the client writes. The route id is
     * part of the key because RedisRateLimiter keys its bucket by this value alone (isAllowed(routeId, id) -> getKeys(id)):
     * two routes resolving the same person would otherwise charge one bucket.
     */
    @Bean
    public KeyResolver principalKeyResolver() {
        return exchange -> {
            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            String routeId = route != null ? route.getId() : "no-route";
            ServerHttpRequest request = exchange.getRequest();
            String userId = request.getHeaders().getFirst("X-User-Id");
            if (userId != null && !userId.isBlank()) {
                return Mono.just(routeId + "|user:" + userId);
            }
            String remote = request.getRemoteAddress() != null && request.getRemoteAddress().getAddress() != null
                    ? request.getRemoteAddress().getAddress().getHostAddress() : "unknown";
            return Mono.just(routeId + "|" + "anon:" + remote);
        };
    }

    public String clientAddress(ServerHttpRequest request) {
        InetSocketAddress peer = request.getRemoteAddress();
        if (peer == null || peer.getAddress() == null) {
            return "unknown";
        }
        if (trustedProxies.stream().anyMatch(proxy -> proxy.matches(peer))) {
            List<String> lines = request.getHeaders().getOrEmpty("X-Forwarded-For");
            String last = lines.isEmpty() ? "" : lines.get(lines.size() - 1);
            String hop = last.substring(last.lastIndexOf(',') + 1).trim();
            if (!hop.isEmpty()) {
                return hop;
            }
        }
        return peer.getAddress().getHostAddress();
    }

    private static IpSubnetFilterRule subnet(String cidr) {
        String[] parts = cidr.trim().split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("gateway.rate-limit.trusted-proxies entry is not a CIDR: " + cidr);
        }
        return new IpSubnetFilterRule(parts[0], Integer.parseInt(parts[1]), IpFilterRuleType.ACCEPT);
    }
}
