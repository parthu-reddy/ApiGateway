package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.security.MapsRoutes;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/** Private Maps is same-origin; global public-asset CORS cannot turn it credentialed. */
public final class MapsCorsFilter implements WebFilter, Ordered {
    @Override public int getOrder(){return Ordered.HIGHEST_PRECEDENCE+5;}
    @Override public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain){
        var policy=MapsRoutes.classify(exchange.getRequest().getURI().getPath());
        if(policy!=null&&!policy.publicRoute()){
            exchange.getResponse().beforeCommit(()->{
                var headers=exchange.getResponse().getHeaders();headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
                headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS);return Mono.empty();
            });
            if(exchange.getRequest().getMethod()==HttpMethod.OPTIONS){
                exchange.getResponse().setStatusCode(HttpStatus.METHOD_NOT_ALLOWED);return exchange.getResponse().setComplete();
            }
        }
        return chain.filter(exchange);
    }
}
