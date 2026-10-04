package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.security.e2e.E2eOtpRunnerAccessFilter;
import com.fooddelivery.apigateway.security.dev.DevOtpAccessFilter;
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
@lombok.extern.slf4j.Slf4j
public class GlobalJwtAuthFilter implements GlobalFilter, Ordered {

    @Value("${jwt.public-key.path:classpath:certs/public.pem}")
    private Resource publicKeyResource;
    
    /**
     * The one implementation of identity signing, shared with every service via the identity-signing
     * module. It lives outside common-library because this gateway cannot depend on that: it drags
     * spring-boot-starter-web onto the classpath and Spring Cloud Gateway then refuses to start
     * (GatewayClassPathWarningAutoConfiguration.SpringMvcFoundOnClasspathConfiguration).
     *
     * The bean's own constructor carries the prod guard and the dev-key fallback, so there is
     * nothing to duplicate here.
     */
    @Autowired
    private com.fooddelivery.common.security.IdentityTokenService identityTokenService;

    @Autowired
    private ReactiveStringRedisTemplate redisTemplate;
    
    @Autowired
    private com.fooddelivery.apigateway.config.RbacConfig rbacConfig;
    @Autowired
    private io.micrometer.core.instrument.MeterRegistry metrics;
    
    private PublicKey publicKey;
    private io.jsonwebtoken.JwtParser jwtParser;

    /**
     * Only revoked sessions are cached. Caching a negative Redis lookup leaves a revocation window
     * in which a just-suspended user can keep using an otherwise valid JWT.
     */
    private final Cache<String, Boolean> blacklistedSessionCache = Caffeine.newBuilder()
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

        // Extract client IP and User-Agent to derive a trusted client fingerprint
        String clientIp = exchange.getRequest().getRemoteAddress() != null ? 
            exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() : "unknown-ip";
        String userAgent = exchange.getRequest().getHeaders().getFirst(HttpHeaders.USER_AGENT);
        if (userAgent == null) userAgent = "unknown-agent";
        
        String derivedFingerprint = java.util.UUID.nameUUIDFromBytes(
            (clientIp + "|" + userAgent).getBytes(StandardCharsets.UTF_8)
        ).toString();
        
        final String finalFingerprint = derivedFingerprint;

        String path = exchange.getRequest().getURI().getPath();
        boolean isE2eOtpLookup = E2eOtpRunnerAccessFilter.isOtpLookupPath(path);
        boolean e2eRunnerValidated = E2eOtpRunnerAccessFilter.isValidated(exchange);
        boolean isDevOtpLookup = DevOtpAccessFilter.isOtpLookupPath(path);

        // Strip sensitive internal headers to prevent spoofing from external clients. The runner
        // credential is retained only for a request already admitted by the e2e-only filter, so
        // IdentityService can enforce the same dedicated secret on its direct port as well.
        ServerWebExchange sanitizedExchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .headers(headers -> {
                            headers.remove("X-User-Id");
                            headers.remove("X-User-Phone");
                            headers.remove("X-User-Roles");
                            headers.remove("X-Session-Id");
                            headers.remove("X-Client-Fingerprint");
                            headers.remove("X-Identity-Signature");
                            headers.remove("X-Issued-At");
                            if (!isE2eOtpLookup || !e2eRunnerValidated) {
                                headers.remove(E2eOtpRunnerAccessFilter.RUNNER_SECRET_HEADER);
                            }
                        })
                        .build())
                .build();

        if (isE2eOtpLookup) {
            if (!e2eRunnerValidated || sanitizedExchange.getRequest().getMethod() != org.springframework.http.HttpMethod.GET) {
                sanitizedExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return sanitizedExchange.getResponse().setComplete();
            }
            return chain.filter(sanitizedExchange);
        }

        // The Dev route is admitted only by its enabled Dev filter, before internal
        // signatures or normal public-route exceptions can bypass its deployment guard.
        if (isDevOtpLookup) {
            if (!DevOtpAccessFilter.isValidated(exchange)
                    || sanitizedExchange.getRequest().getMethod() != org.springframework.http.HttpMethod.GET) {
                sanitizedExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return sanitizedExchange.getResponse().setComplete();
            }
            return chain.filter(sanitizedExchange);
        }
        
        // 1. Check for valid internal service-to-service IdentityToken
        String incUserId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
        String incRoles = exchange.getRequest().getHeaders().getFirst("X-User-Roles");
        String incPhone = exchange.getRequest().getHeaders().getFirst("X-User-Phone");
        String incSessionId = exchange.getRequest().getHeaders().getFirst("X-Session-Id");
        String incSignature = exchange.getRequest().getHeaders().getFirst("X-Identity-Signature");
        String incIssuedAtStr = exchange.getRequest().getHeaders().getFirst("X-Issued-At");

        if (incSignature != null && !incSignature.isEmpty()) {
            long issuedAt = 0L;
            if (incIssuedAtStr != null) {
                try { issuedAt = Long.parseLong(incIssuedAtStr); } catch (NumberFormatException ignored) {}
            }
            if (identityTokenService.verify(incSignature, incUserId, incRoles, incPhone, incSessionId, issuedAt)) {
                log.info("GlobalJwtAuthFilter - Valid Internal Service Request: path={}", path);
                ServerWebExchange internalExchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                        .header("X-Client-Fingerprint", finalFingerprint)
                        .build())
                    .build();
                return chain.filter(internalExchange);
            }
        }

        // 2. Only the administrator namespace is externally reachable under /internal.
        if (path.startsWith("/api/v1/internal/")) {
            if (!path.startsWith("/api/v1/internal/admin/")) {
                log.warn("GlobalJwtAuthFilter 403 FORBIDDEN: External access to internal path={}", path);
                sanitizedExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return sanitizedExchange.getResponse().setComplete();
            }
        }
        
        boolean isPublic = false;
        // Public endpoints (Auth, Home, Static, Webhooks, Actuator, Test)
        if ((sanitizedExchange.getRequest().getMethod()==org.springframework.http.HttpMethod.POST
                && (path.equals("/api/v1/auth/otp") || path.equals("/api/v1/auth/session")))
                || path.equals("/") || path.endsWith(".html") || path.contains("/webhooks/") || path.contains("/api/v1/webhooks/") || path.startsWith("/actuator/") || path.startsWith("/api/test/") || path.startsWith("/olamaps/")) {
            isPublic = true;
        }
        
        // Swagger / OpenAPI endpoints
        if (path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") || path.startsWith("/webjars/") || path.startsWith("/service-docs/")) {
            isPublic = true;
        }
        
        // Public catalog endpoints (GET only)
        if (sanitizedExchange.getRequest().getMethod().matches("GET")) {
            if (path.equals("/api/v1/brands") || path.startsWith("/api/v1/brands/") || 
                path.equals("/api/v1/restaurants") || path.startsWith("/api/v1/restaurants/") || 
                path.equals("/api/v1/outlets") || path.startsWith("/api/v1/outlets/") || 
                path.equals("/api/v1/categories") || path.startsWith("/api/v1/categories/") || 
                path.startsWith("/api/places/") || path.equals("/api/config/maps-key")) {
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
                Object rawVersion=claims.get("ev");
                if (sessionId == null || sessionId.isBlank() || userId==null
                        || !(rawVersion instanceof Integer || rawVersion instanceof Long)
                        || ((Number)rawVersion).longValue()<0) {
                    return isPublic ? chain.filter(sanitizedExchange) : handleUnauthorized(sanitizedExchange);
                }
                long tokenVersion=((Number)rawVersion).longValue();
                
                @SuppressWarnings("unchecked")
                List<String> rolesList = claims.get("roles", List.class);
                String roles = (rolesList != null) ? String.join(",", rolesList) : "";
                
                long issuedAt = claims.getIssuedAt() != null ? claims.getIssuedAt().getTime() : 0L;

                Boolean isBlacklistedLocal = blacklistedSessionCache.getIfPresent(sessionId);
                if (Boolean.TRUE.equals(isBlacklistedLocal)) {
                    return handleUnauthorized(sanitizedExchange);
                }

                final boolean publicRequest=isPublic;
                // Check version before role gates: a newly approved person may still have an old
                // token without the requested portal role and must be allowed to refresh it.
                return redisTemplate.opsForValue().multiGet(List.of("BLACKLIST:SESSION:"+sessionId,"ENTITLEMENTS_VERSION:"+userId,"USER_SESSIONS:"+userId))
                        .defaultIfEmpty(List.of())
                        .onErrorResume(error -> {
                            log.warn("Unable to verify session state; denying request failure={}",error.getClass().getSimpleName());
                            return Mono.just(List.of());
                        })
                        .flatMap(values -> {
                            if (values.size()!=3) return handleUnauthorized(sanitizedExchange);
                            if (values.get(0)!=null) {
                                blacklistedSessionCache.put(sessionId, true);
                                return handleUnauthorized(sanitizedExchange);
                            }
                            if (!com.fooddelivery.apigateway.security.PersonSessionVerifier.matches(values.get(2), sessionId,
                                    rolesList != null && rolesList.contains("ADMIN"),
                                    claims.getExpiration() == null ? null : claims.getExpiration().toInstant()))
                                return handleUnauthorized(sanitizedExchange);
                            long storedVersion;
                            try {storedVersion=values.get(1)==null?0:Long.parseLong(values.get(1));}
                            catch (NumberFormatException ex) {return handleUnauthorized(sanitizedExchange);}
                            if (storedVersion<0) return handleUnauthorized(sanitizedExchange);
                            boolean versionExempt=path.equals("/api/v1/auth/session/refresh") || path.equals("/api/v1/auth/logout");
                            if (!versionExempt && tokenVersion<storedVersion) {
                                metrics.counter("gateway.entitlements.stale_tokens").increment();
                                sanitizedExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                sanitizedExchange.getResponse().getHeaders().set("X-Auth-Reason","ENTITLEMENTS_CHANGED");
                                return sanitizedExchange.getResponse().setComplete();
                            }
                            if (!publicRequest && !hasRequiredRole(path,rolesList)) {
                                sanitizedExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                return sanitizedExchange.getResponse().setComplete();
                            }
                            return proceedWithValidToken(sanitizedExchange, chain, userId, phone, roles, sessionId, rolesList, path, finalFingerprint, issuedAt);
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
    

    private Mono<Void> proceedWithValidToken(ServerWebExchange exchange, GatewayFilterChain chain, String userId, String phone, String roles, String sessionId, List<String> rolesList, String path, String fingerprint, long issuedAt) {
        String upgradeHeader = exchange.getRequest().getHeaders().getFirst("Upgrade");
        if ("websocket".equalsIgnoreCase(upgradeHeader)) {
            log.info("GlobalJwtAuthFilter SUCCESS (WebSocket Upgrade): path={} roles={} userId={}", path, rolesList, userId);
        } else {
            log.info("GlobalJwtAuthFilter SUCCESS: path={} roles={}", path, rolesList);
        }
        
        String signature = identityTokenService.sign(userId, roles, phone, sessionId, issuedAt);
        
        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Phone", phone)
                        .header("X-User-Roles", roles)
                        .header("X-Session-Id", sessionId != null ? sessionId : "")
                        .header("X-Client-Fingerprint", fingerprint)
                        .header("X-Identity-Signature", signature)
                        .header("X-Issued-At", String.valueOf(issuedAt))
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
                    if (path.equals(allowedPath) || path.startsWith(allowedPath + "/")) {
                        return true;
                    }
                }
            }
        }
        
        // Check "AUTHENTICATED" pseudo-role (any logged in user)
        List<String> authPaths = rules.get("authenticated");
        if (authPaths != null) {
            for (String allowedPath : authPaths) {
                if (path.equals(allowedPath) || path.startsWith(allowedPath + "/")) {
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
