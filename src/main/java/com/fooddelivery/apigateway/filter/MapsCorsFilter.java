package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.security.MapsRoutes;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Private Maps is same-origin; global public-asset CORS cannot turn it credentialed.
 * Public map data (snapshot tiles/TileJSON/archive, styles, glyphs, sprites) is
 * credentialless and served to any origin, so an independent client hosted
 * elsewhere can render it: the request's Origin is dropped before the Gateway's
 * first-party CORS check and the response carries exactly the backends' "*".
 * Other public Maps routes carry exactly one Access-Control-Allow-Origin: the
 * Gateway's configured-origin decision replaces a backend's "*" instead of being
 * appended to it. A public preflight grants only that route's own methods.
 */
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
        if(policy!=null&&publicMapData(policy)){
            var request=exchange.getRequest().mutate().headers(h->h.remove(HttpHeaders.ORIGIN)).build();
            var shared=exchange.mutate().request(request).build();
            shared.getResponse().beforeCommit(()->{
                var headers=shared.getResponse().getHeaders();
                headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,"*");
                headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS);
                narrow(headers,policy);
                return Mono.empty();
            });
            return chain.filter(shared);
        }
        if(policy!=null&&policy.publicRoute()){
            exchange.getResponse().beforeCommit(()->{
                var headers=exchange.getResponse().getHeaders();
                List<String> origins=values(headers.get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
                List<String> granted=origins.stream().filter(v->!v.equals("*")).distinct().toList();
                if(origins.size()>1){
                    // Several values are invalid CORS; a specific Gateway grant wins over a backend wildcard.
                    headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
                    if(granted.size()==1)headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,granted.get(0));
                }
                headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS);
                narrow(headers,policy);
                return Mono.empty();
            });
        }
        return chain.filter(exchange);
    }
    static boolean publicMapData(MapsRoutes.Policy policy){
        return policy.publicRoute()&&(policy.backend().equals("public")||policy.backend().equals("assets"));
    }
    private static void narrow(HttpHeaders headers, MapsRoutes.Policy policy){
        if(headers.containsKey(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)){
            headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,policy.methods().stream().filter(m->m!=HttpMethod.OPTIONS)
                    .map(HttpMethod::name).sorted().collect(Collectors.joining(",")));
        }
    }
    private static List<String> values(List<String> raw){
        if(raw==null)return List.of();
        return raw.stream().flatMap(v->Arrays.stream(v.split(","))).map(String::trim).filter(v->!v.isEmpty()).toList();
    }
}
