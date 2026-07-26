package com.fooddelivery.apigateway.filter;

import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
@Component
public class GlobalJwtAuthFilter implements GlobalFilter, Ordered {
    private static final Logger log = LoggerFactory.getLogger(GlobalJwtAuthFilter.class);

    @Value("${jwt.public-key.path:classpath:certs/public.pem}")
    private Resource publicKeyResource;
    
    @Autowired
    private ReactiveStringRedisTemplate redisTemplate;
    
    @Autowired
    private com.fooddelivery.apigateway.config.RbacConfig rbacConfig;
    
    private PublicKey publicKey;
    private io.jsonwebtoken.JwtParser jwtParser;

    private final Cache<String, Boolean> blacklistCache = Caffeine.newBuilder()
            .expireAfterWrite(30, TimeUnit.SECONDS)
            .maximumSize(10000)
            .build();

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
            
            // Build the parser once and reuse it for performance
            this.jwtParser = Jwts.parserBuilder()
                    .setSigningKey(this.publicKey)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RSA public key", e);
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (exchange.getRequest().getMethod().matches("OPTIONS")) {
            return chain.filter(exchange);
        }

        // Strip sensitive internal headers to prevent spoofing from external clients
        ServerWebExchange sanitizedExchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .headers(headers -> {
                            headers.remove("X-User-Id");
                            headers.remove("X-User-Phone");
                            headers.remove("X-User-Roles");
                            headers.remove("X-Session-Id");
                        })
                        .build())
                .build();

        String path = sanitizedExchange.getRequest().getURI().getPath();
        
        boolean isPublic = false;
        // Public endpoints (Auth, Home, Static, Webhooks, Actuator, Test)
        if (path.equals("/") || path.equals("/api/v1/internal/auth/initiate") || path.equals("/api/v1/internal/auth/verify") || path.equals("/api/v1/internal/auth/admin/otp") || path.endsWith(".html") || path.contains("/webhooks/") || path.contains("/api/v1/webhooks/") || path.startsWith("/actuator/") || path.startsWith("/api/test/")) {
            isPublic = true;
        }
        
        // Public catalog endpoints (GET only)
        if (sanitizedExchange.getRequest().getMethod().matches("GET")) {
            if (path.equals("/api/v1/brands") || path.startsWith("/api/v1/brands/") || 
                path.equals("/api/v1/restaurants") || path.startsWith("/api/v1/restaurants/") || 
                path.equals("/api/v1/outlets") || path.startsWith("/api/v1/outlets/") || 
                path.equals("/api/v1/categories") || path.startsWith("/api/v1/categories/") || 
                path.startsWith("/api/places/")) {
                isPublic = true;
            }
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
                Claims claims = jwtParser.parseClaimsJws(token).getBody();

                String userId = claims.getSubject();
                String phone = claims.get("phone", String.class);
                String sessionId = claims.get("sessionId", String.class);
                
                @SuppressWarnings("unchecked")
                List<String> rolesList = claims.get("roles", List.class);
                String roles = (rolesList != null) ? String.join(",", rolesList) : "";
                
                // Role-Based Access Control
                if (!isPublic && !hasRequiredRole(path, rolesList)) {
                    log.warn("GlobalJwtAuthFilter 403 FORBIDDEN: path={} roles={}", path, rolesList);
                    sanitizedExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return sanitizedExchange.getResponse().setComplete();
                }

                Boolean isBlacklistedLocal = blacklistCache.getIfPresent(sessionId);
                if (Boolean.TRUE.equals(isBlacklistedLocal)) {
                    return handleUnauthorized(sanitizedExchange);
                } else if (Boolean.FALSE.equals(isBlacklistedLocal)) {
                    return proceedWithValidToken(sanitizedExchange, chain, userId, phone, roles, sessionId, rolesList, path);
                }

                return redisTemplate.hasKey("BLACKLIST:SESSION:" + sessionId)
                        .flatMap(isBlacklisted -> {
                            blacklistCache.put(sessionId, isBlacklisted);
                            if (Boolean.TRUE.equals(isBlacklisted)) {
                                return handleUnauthorized(sanitizedExchange);
                            }
                            return proceedWithValidToken(sanitizedExchange, chain, userId, phone, roles, sessionId, rolesList, path);
                        });
            } catch (Exception e) {
                if (isPublic) {
                    return chain.filter(sanitizedExchange);
                }
                return handleUnauthorized(sanitizedExchange);
            }
        }

        if (isPublic) {
            return chain.filter(sanitizedExchange);
        }

        return handleUnauthorized(sanitizedExchange);
    }
    
    private Mono<Void> proceedWithValidToken(ServerWebExchange exchange, GatewayFilterChain chain, String userId, String phone, String roles, String sessionId, List<String> rolesList, String path) {
        log.info("GlobalJwtAuthFilter SUCCESS: path={} roles={}", path, rolesList);
        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Phone", phone)
                        .header("X-User-Roles", roles)
                        .header("X-Session-Id", sessionId != null ? sessionId : "")
                        .build())
                .build();
                
        return chain.filter(mutatedExchange);
    }
    
    private boolean hasRequiredRole(String path, List<String> roles) {
        if (roles == null) return false;
        
        if (roles.contains("ADMIN")) {
            return true;
        }

        Map<String, List<String>> rules = rbacConfig.getRules();
        if (rules == null || rules.isEmpty()) {
            // Fallback to strict default-deny if configuration is missing
            return false;
        }

        // Iterate through configured roles to see if the user's role matches any allowed route
        for (String userRole : roles) {
            String roleKey = userRole.toLowerCase();
            List<String> allowedPaths = rules.get(roleKey);
            if (allowedPaths != null) {
                for (String allowedPath : allowedPaths) {
                    if (path.startsWith(allowedPath)) {
                        return true;
                    }
                }
            }
        }
        
        // Check "AUTHENTICATED" pseudo-role (any logged in user)
        List<String> authPaths = rules.get("authenticated");
        if (authPaths != null) {
            for (String allowedPath : authPaths) {
                if (path.startsWith(allowedPath)) {
                    return true;
                }
            }
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
