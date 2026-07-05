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
import java.util.List;

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
        
        // Public endpoints (Note: Auth endpoints will be hosted by downstream services e.g., /api/v1/customers/auth/initiate)
        if (path.contains("/auth/initiate") || path.contains("/auth/verify")) {
            return chain.filter(sanitizedExchange);
        }
        
        // Public catalog endpoints (GET only)
        if (sanitizedExchange.getRequest().getMethod().matches("GET") && 
            (path.contains("/api/v1/brands") || path.contains("/api/v1/restaurants") || path.contains("/api/v1/outlets"))) {
            return chain.filter(sanitizedExchange);
        }
        

        if (!sanitizedExchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            sanitizedExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return sanitizedExchange.getResponse().setComplete();
        }

        String authHeader = sanitizedExchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            
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
                sanitizedExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return sanitizedExchange.getResponse().setComplete();
            }
        }

        sanitizedExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return sanitizedExchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // Run before routing
    }
}
