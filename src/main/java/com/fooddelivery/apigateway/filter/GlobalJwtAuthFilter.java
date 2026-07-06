package com.fooddelivery.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.net.URI;
import java.util.List;
import org.springframework.http.MediaType;

import jakarta.annotation.PostConstruct;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;
@Component
public class GlobalJwtAuthFilter implements GlobalFilter, Ordered {

    @Value("${jwt.public-key.path:classpath:certs/public.pem}")
    private Resource publicKeyResource;
    
    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        try {
            byte[] keyBytes = FileCopyUtils.copyToByteArray(publicKeyResource.getInputStream());
            String keyString = new String(keyBytes, StandardCharsets.UTF_8)
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decodedKey = Base64.getDecoder().decode(keyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RSA public key", e);
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Strip sensitive internal headers to prevent spoofing from external clients
        ServerWebExchange sanitizedExchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .headers(headers -> {
                            headers.remove("X-User-Id");
                            headers.remove("X-User-Phone");
                            headers.remove("X-User-Roles");
                        })
                        .build())
                .build();

        String path = sanitizedExchange.getRequest().getURI().getPath();
        
        // Public endpoints (Auth, Home, Static, Webhooks, Actuator, Test)
        if (path.equals("/") || path.contains("/auth/initiate") || path.contains("/auth/verify") || path.endsWith(".html") || path.contains("/webhooks/") || path.contains("/api/v1/webhooks/") || path.startsWith("/actuator/") || path.startsWith("/api/test/")) {
            return chain.filter(sanitizedExchange);
        }
        
        // Public catalog endpoints (GET only)
        if (sanitizedExchange.getRequest().getMethod().matches("GET") && 
            (path.contains("/api/v1/brands") || path.contains("/api/v1/restaurants") || path.contains("/api/v1/outlets"))) {
            return chain.filter(sanitizedExchange);
        }
        

        String token = null;
        if (sanitizedExchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            String authHeader = sanitizedExchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            }
        } else if (sanitizedExchange.getRequest().getQueryParams().containsKey("token")) {
            token = sanitizedExchange.getRequest().getQueryParams().getFirst("token");
        }

        if (token != null && !token.isEmpty()) {
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(publicKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String userId = claims.getSubject();
                String phone = claims.get("phone", String.class);
                
                @SuppressWarnings("unchecked")
                List<String> rolesList = claims.get("roles", List.class);
                String roles = (rolesList != null) ? String.join(",", rolesList) : "";
                
                // Role-Based Access Control
                if (!hasRequiredRole(path, rolesList)) {
                    sanitizedExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return sanitizedExchange.getResponse().setComplete();
                }

                // Add trusted headers for downstream microservices
                ServerWebExchange mutatedExchange = sanitizedExchange.mutate()
                        .request(sanitizedExchange.getRequest().mutate()
                                .header("X-User-Id", userId)
                                .header("X-User-Phone", phone)
                                .header("X-User-Roles", roles)
                                .build())
                        .build();
                        
                return chain.filter(mutatedExchange);
            } catch (Exception e) {
                return handleUnauthorized(sanitizedExchange);
            }
        }

        return handleUnauthorized(sanitizedExchange);
    }
    
    private boolean hasRequiredRole(String path, List<String> roles) {
        if (roles == null) return false;
        
        if (path.startsWith("/api/v1/customers") || path.startsWith("/api/v1/orders") || path.startsWith("/api/v1/places")) {
            return roles.contains("CUSTOMER");
        }
        if (path.startsWith("/api/v1/restaurants") || path.startsWith("/api/v1/brands") || path.startsWith("/api/v1/outlets")) {
            return roles.contains("RESTAURANT");
        }
        if (path.startsWith("/api/v1/delivery") || path.startsWith("/api/delivery") || path.startsWith("/api/logistics") || path.startsWith("/api/fleet") || path.startsWith("/api/places") || path.startsWith("/api/maps")) {
            return roles.contains("DELIVERY") || ((path.startsWith("/api/places") || path.startsWith("/api/maps")) && (roles.contains("CUSTOMER") || roles.contains("RESTAURANT")));
        }
        
        // Strict Default-Deny for unmapped gateway routes
        return false;
    }
    
    private Mono<Void> handleUnauthorized(ServerWebExchange exchange) {
        List<String> accept = exchange.getRequest().getHeaders().get(HttpHeaders.ACCEPT);
        if (accept != null && accept.stream().anyMatch(a -> a.contains(MediaType.TEXT_HTML_VALUE))) {
            exchange.getResponse().setStatusCode(HttpStatus.SEE_OTHER);
            exchange.getResponse().getHeaders().setLocation(URI.create("/"));
            return exchange.getResponse().setComplete();
        }
        
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // Run before routing
    }
}
