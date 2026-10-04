package com.fooddelivery.apigateway.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fooddelivery.apigateway.config.RbacConfig;
import com.fooddelivery.apigateway.security.e2e.E2eOtpRunnerAccessFilter;
import com.fooddelivery.common.security.IdentityTokenService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

class GlobalJwtAuthFilterRevocationTest {

    private final ReactiveStringRedisTemplate redis = mock(ReactiveStringRedisTemplate.class);
    private final IdentityTokenService identityTokenService = mock(IdentityTokenService.class);
    private final AtomicInteger passedToChain = new AtomicInteger();
    private GlobalJwtAuthFilter filter;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        filter = new GlobalJwtAuthFilter();
        ReflectionTestUtils.setField(filter, "publicKeyResource", new ByteArrayResource(publicKeyPem()));
        ReflectionTestUtils.setField(filter, "identityTokenService", identityTokenService);
        ReflectionTestUtils.setField(filter, "redisTemplate", redis);
        RbacConfig rbac = new RbacConfig();
        rbac.setRules(Map.of("authenticated", List.of("/api/v1/users")));
        ReflectionTestUtils.setField(filter, "rbacConfig", rbac);
        when(identityTokenService.sign(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyLong())).thenReturn("gateway-signature");
        filter.init();
    }

    @Test
    void explicitRegistrationCanReachIdentityWithoutAnExistingSession() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/internal/auth/register")
                .header("X-Calling-Service", "RESTAURANT").build());
        filter.filter(exchange, this::passThrough).block();
        assertEquals(1, passedToChain.get());
        assertNull(exchange.getResponse().getStatusCode());
    }

    @Test
    void registrationDoesNotExposeOtherInternalRoutes() {
        var exchange = exchange("/api/v1/internal/auth/register/admin", null);
        filter.filter(exchange, this::passThrough).block();
        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        assertEquals(0, passedToChain.get());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={
        "/api/v1/internal/organisations/22222222-2222-2222-2222-222222222222/members",
        "/api/v1/internal/organisations/22222222-2222-2222-2222-222222222222/members/11111111-1111-1111-1111-111111111111",
        "/api/v1/internal/users/11111111-1111-1111-1111-111111111111/organisations",
        "/api/v1/internal/restaurants/users/11111111-1111-1111-1111-111111111111/outlets?permission=ORG_VIEW",
        "/api/v1/internal/restaurants/outlets/22222222-2222-2222-2222-222222222222/organisation"
    })
    void organisationInternalRoutesRejectExternalTrafficEvenWithValidCustomerToken(String path) {
        var exchange=exchange(path,token("session-org"));
        filter.filter(exchange,this::passThrough).block();
        assertEquals(HttpStatus.FORBIDDEN,exchange.getResponse().getStatusCode());
        assertEquals(0,passedToChain.get());
    }

    @Test
    void removedDevOtpEndpointIsRejectedBeforeItReachesIdentityService() {
        MockServerWebExchange exchange = exchange("/api/v1/internal/auth/admin/otp", null);

        filter.filter(exchange, this::passThrough).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        assertEquals(0, passedToChain.get());
    }

    @Test
    void serviceAuthenticatedE2eOtpEndpointIsAlsoRejectedForExternalTraffic() {
        MockServerWebExchange exchange = exchange("/api/v1/internal/e2e/auth/otp", null);

        filter.filter(exchange, this::passThrough).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        assertEquals(0, passedToChain.get());
    }

    @Test
    void validatedE2eRunnerRequestCanReachTheIdentityRoute() {
        MockServerWebExchange exchange = exchange("/api/v1/internal/e2e/auth/otp", null);
        exchange.getAttributes().put(E2eOtpRunnerAccessFilter.VALIDATED_ATTRIBUTE, Boolean.TRUE);

        filter.filter(exchange, this::passThrough).block();

        assertEquals(1, passedToChain.get());
    }

    @Test
    void runnerSecretHeaderIsNotForwardedOutsideTheValidatedE2eRoute() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/")
                .header(E2eOtpRunnerAccessFilter.RUNNER_SECRET_HEADER, "runner-secret")
                .build());
        AtomicReference<String> forwardedSecret = new AtomicReference<>();

        filter.filter(exchange, forwarded -> {
            forwardedSecret.set(forwarded.getRequest().getHeaders()
                    .getFirst(E2eOtpRunnerAccessFilter.RUNNER_SECRET_HEADER));
            return Mono.empty();
        }).block();

        assertNull(forwardedSecret.get());
    }

    @Test
    void gatewayDoesNotCacheNegativeRevocationLookups() {
        String sessionId = "session-123";
        when(redis.hasKey("BLACKLIST:SESSION:" + sessionId))
                .thenReturn(Mono.just(false), Mono.just(true));

        MockServerWebExchange first = exchange("/api/v1/users/profile", token(sessionId));
        filter.filter(first, this::passThrough).block();
        assertEquals(1, passedToChain.get());

        MockServerWebExchange second = exchange("/api/v1/users/profile", token(sessionId));
        filter.filter(second, this::passThrough).block();

        verify(redis, times(2)).hasKey("BLACKLIST:SESSION:" + sessionId);
        assertEquals(HttpStatus.UNAUTHORIZED, second.getResponse().getStatusCode());
        assertEquals(1, passedToChain.get());
    }
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={"../Deployment/api-gateway.yml","src/main/resources/application.yml"})
    void deployedAndFallbackPoliciesAllowAnAuthenticatedApplicantButDenyAdminAndServiceOnlyReads(String file) throws Exception {
        var env=new org.springframework.core.env.StandardEnvironment();
        for(var source:new org.springframework.boot.env.YamlPropertySourceLoader().load("partner-rbac",new org.springframework.core.io.FileSystemResource(file)))
            env.getPropertySources().addFirst(source);
        var rules=org.springframework.boot.context.properties.bind.Binder.get(env).bind("rbac",
                org.springframework.boot.context.properties.bind.Bindable.of(RbacConfig.class)).orElseThrow(IllegalStateException::new);
        ReflectionTestUtils.setField(filter,"rbacConfig",rules);
        when(redis.hasKey("BLACKLIST:SESSION:partner-test")).thenReturn(Mono.just(false));
        for(String path:List.of("/api/v1/restaurant-onboarding/organisations/x/application","/api/v1/delivery-onboarding/application","/api/v1/verification/upload-url")) {
            int before=passedToChain.get();var anonymous=exchange(path,null);filter.filter(anonymous,this::passThrough).block();
            assertEquals(HttpStatus.UNAUTHORIZED,anonymous.getResponse().getStatusCode());assertEquals(before,passedToChain.get());
            var signed=exchange(path,token("partner-test"));filter.filter(signed,this::passThrough).block();
            assertNull(signed.getResponse().getStatusCode());assertEquals(before+1,passedToChain.get());
        }
        for(String path:List.of("/api/v1/internal/admin/restaurant-applications","/api/v1/internal/admin/delivery-applications",
                "/api/v1/internal/admin/verification/documents/x/download-url","/api/v1/internal/delivery-applications/x/context",
                "/api/v1/internal/brands/x/verification-request")) {
            int before=passedToChain.get();var outsider=exchange(path,token("partner-test"));filter.filter(outsider,this::passThrough).block();
            assertEquals(HttpStatus.FORBIDDEN,outsider.getResponse().getStatusCode(),path);assertEquals(before,passedToChain.get());
        }
    }

    private Mono<Void> passThrough(ServerWebExchange ignored) {
        passedToChain.incrementAndGet();
        return Mono.empty();
    }

    private MockServerWebExchange exchange(String path, String token) {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get(path);
        if (token != null) {
            request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return MockServerWebExchange.from(request.build());
    }

    private String token(String sessionId) {
        return Jwts.builder()
                .setSubject("11111111-1111-1111-1111-111111111111")
                .claim("phone", "9000000001")
                .claim("roles", List.of("CUSTOMER"))
                .claim("sessionId", sessionId)
                .setIssuedAt(new java.util.Date())
                .setExpiration(new java.util.Date(System.currentTimeMillis() + 60_000))
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
    }

    private byte[] publicKeyPem() {
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(keyPair.getPublic().getEncoded());
        return ("-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n")
                .getBytes(StandardCharsets.UTF_8);
    }
}
