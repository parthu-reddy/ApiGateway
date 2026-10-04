package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.config.RbacConfig;
import com.fooddelivery.common.security.IdentityTokenService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.data.redis.core.*;
import org.springframework.http.*;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class GlobalJwtAuthFilterEntitlementsTest {
    private static KeyPair keys;
    private static final String USER="11111111-1111-1111-1111-111111111111", SID="owned-session";
    private static final Instant NOW=Instant.parse("2026-10-04T12:00:00Z");
    private static final List<String> LOOKUP=List.of("BLACKLIST:SESSION:"+SID,"ENTITLEMENTS_VERSION:"+USER,"USER_SESSIONS:"+USER);
    private final ReactiveStringRedisTemplate redis=mock(ReactiveStringRedisTemplate.class);
    private final ReactiveValueOperations<String,String> values=mock(ReactiveValueOperations.class);
    private final IdentityTokenService identity=mock(IdentityTokenService.class);
    private final AtomicInteger routed=new AtomicInteger();
    private final SimpleMeterRegistry metrics=new SimpleMeterRegistry();
    private GlobalJwtAuthFilter filter;

    @BeforeAll static void rsa() throws Exception {keys=KeyPairGenerator.getInstance("RSA").generateKeyPair();}
    @BeforeEach void setup() {
        filter=new GlobalJwtAuthFilter();
        String pem="-----BEGIN PUBLIC KEY-----\n"+Base64.getEncoder().encodeToString(keys.getPublic().getEncoded())+"\n-----END PUBLIC KEY-----";
        ReflectionTestUtils.setField(filter,"publicKeyResource",new ByteArrayResource(pem.getBytes(StandardCharsets.UTF_8)));
        ReflectionTestUtils.setField(filter,"redisTemplate",redis);
        ReflectionTestUtils.setField(filter,"identityTokenService",identity);
        ReflectionTestUtils.setField(filter,"metrics",metrics);
        var rules=new RbacConfig();rules.setRules(Map.of("authenticated",List.of("/api/v1/users","/api/v1/auth"),
                "restaurant",List.of("/api/v1/restaurant-private"),"customer",List.of("/ws/chat")));
        ReflectionTestUtils.setField(filter,"rbacConfig",rules);
        when(redis.opsForValue()).thenReturn(values);
        when(identity.sign(any(),any(),any(),any(),anyLong())).thenReturn("verified-signature");
        filter.init();
        ReflectionTestUtils.setField(filter,"jwtParser",Jwts.parserBuilder().setSigningKey(keys.getPublic())
                .setClock(()->Date.from(NOW)).build());
        stored(null,"4");
    }
    @Test void staleRolesRefreshBeforeRoleDenialIncludingHtmlRequests() {
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/restaurant-private/orders")
                .header(HttpHeaders.AUTHORIZATION,"Bearer "+token(3,NOW.plusSeconds(60))).header(HttpHeaders.ACCEPT,MediaType.TEXT_HTML_VALUE));
        filter.filter(exchange,e->{routed.incrementAndGet();return Mono.empty();}).block();
        assertEquals(HttpStatus.UNAUTHORIZED,exchange.getResponse().getStatusCode());
        assertEquals("ENTITLEMENTS_CHANGED",exchange.getResponse().getHeaders().getFirst("X-Auth-Reason"));
        assertEquals(0,routed.get());assertEquals(1,metrics.counter("gateway.entitlements.stale_tokens").count());
        verify(values).multiGet(LOOKUP);verify(redis,never()).hasKey(anyString());
    }
    @ParameterizedTest @ValueSource(longs={4,5})
    void equalOrHigherVersionPasses(long version) {
        var exchange=run("/api/v1/users/profile",token(version,NOW.plusSeconds(60)),false);
        assertEquals(1,routed.get());assertNull(exchange.getResponse().getStatusCode());
        verify(values).multiGet(LOOKUP);
    }
    @Test void missingKeyIsZeroButExpiredPreBumpTokenCannotPass() {
        stored(null,null);
        ReflectionTestUtils.setField(filter,"jwtParser",Jwts.parserBuilder().setSigningKey(keys.getPublic()).setClock(()->Date.from(NOW.plus(Duration.ofDays(2)))).build());
        var expired=run("/api/v1/users/profile",token(0,NOW.plus(Duration.ofDays(1))),false);
        assertEquals(HttpStatus.UNAUTHORIZED,expired.getResponse().getStatusCode());verifyNoInteractions(values);
        ReflectionTestUtils.setField(filter,"jwtParser",Jwts.parserBuilder().setSigningKey(keys.getPublic()).setClock(()->Date.from(NOW)).build());
        var current=run("/api/v1/users/profile",token(0,NOW.plusSeconds(60)),false);
        assertEquals(1,routed.get());assertNull(current.getResponse().getStatusCode());verify(values).multiGet(LOOKUP);
    }
    @ParameterizedTest @ValueSource(strings={"/api/v1/auth/session/refresh","/api/v1/auth/logout"})
    void versionExemptEndpointsStillCheckBlacklist(String path) {
        var refresh=run(path,token(0,NOW.plusSeconds(60)),false);assertNull(refresh.getResponse().getStatusCode());
        stored("true","4");var denied=run(path,token(0,NOW.plusSeconds(60)),false);
        assertEquals(HttpStatus.UNAUTHORIZED,denied.getResponse().getStatusCode());assertEquals(1,routed.get());
        verify(values,times(2)).multiGet(LOOKUP);
    }
    @Test void websocketUsesSameVersionCheck() {
        var stale=run("/ws/chat",token(3,NOW.plusSeconds(60)),true);
        assertEquals(HttpStatus.UNAUTHORIZED,stale.getResponse().getStatusCode());assertEquals(0,routed.get());
        assertEquals("ENTITLEMENTS_CHANGED",stale.getResponse().getHeaders().getFirst("X-Auth-Reason"));
    }
    @Test void freshWebsocketIsSignedAndForwarded() {
        var exchange=request("/ws/chat",token(4,NOW.plusSeconds(60)),true);
        filter.filter(exchange,e->{assertEquals(USER,e.getRequest().getHeaders().getFirst("X-User-Id"));
            assertEquals("verified-signature",e.getRequest().getHeaders().getFirst("X-Identity-Signature"));routed.incrementAndGet();return Mono.empty();}).block();
        assertEquals(1,routed.get());verify(values).multiGet(LOOKUP);
    }
    @Test void redisFailureDeniesButDoesNotHideDownstreamFailure() {
        when(values.multiGet(LOOKUP)).thenReturn(Mono.error(new IllegalStateException("read failed")));
        var denied=run("/api/v1/users/profile",token(4,NOW.plusSeconds(60)),false);
        assertEquals(HttpStatus.UNAUTHORIZED,denied.getResponse().getStatusCode());assertEquals(0,routed.get());
        stored(null,"4");
        assertThrows(IllegalArgumentException.class,()->filter.filter(request("/api/v1/users/profile",token(4,NOW.plusSeconds(60)),false),
                e->Mono.error(new IllegalArgumentException("downstream"))).block());
    }
    @ParameterizedTest @ValueSource(strings={"broken","-1","9223372036854775808"})
    void malformedStoredVersionDenies(String version) {
        stored(null,version);assertEquals(HttpStatus.UNAUTHORIZED,run("/api/v1/users/profile",token(4,NOW.plusSeconds(60)),false).getResponse().getStatusCode());
        assertEquals(0,routed.get());
    }
    @Test void versionReadsAreNeverNegativelyCached() {
        assertNull(run("/api/v1/users/profile",token(4,NOW.plusSeconds(60)),false).getResponse().getStatusCode());
        stored(null,"5");assertEquals(HttpStatus.UNAUTHORIZED,run("/api/v1/users/profile",token(4,NOW.plusSeconds(60)),false).getResponse().getStatusCode());
        verify(values,times(2)).multiGet(LOOKUP);assertEquals(1,routed.get());
    }
    @Test void protectedTokenWithoutVersionCannotPass() {
        assertEquals(HttpStatus.UNAUTHORIZED,run("/api/v1/users/profile",token(null,NOW.plusSeconds(60)),false).getResponse().getStatusCode());verifyNoInteractions(values);
    }
    @ParameterizedTest @ValueSource(strings={"/api/v1/auth/otp","/api/v1/auth/session"})
    void onlyPostLoginEndpointsAreAnonymous(String path) {
        var post=MockServerWebExchange.from(MockServerHttpRequest.post(path));
        filter.filter(post,e->{routed.incrementAndGet();return Mono.empty();}).block();assertEquals(1,routed.get());
        assertEquals(HttpStatus.UNAUTHORIZED,run(path,null,false).getResponse().getStatusCode());
    }
    @Test void aTokenCannotSurviveLostSessionStateOrACompleteDevWipe() {
        when(values.multiGet(LOOKUP)).thenReturn(Mono.just(Arrays.asList(null,null,null)));
        assertEquals(HttpStatus.UNAUTHORIZED,run("/api/v1/users/profile",token(0,NOW.plusSeconds(60)),false).getResponse().getStatusCode());
        assertEquals(0,routed.get());verify(values).multiGet(LOOKUP);
    }
    @Test void anotherPersonsSessionCannotAuthorizeThisToken() {
        when(values.multiGet(LOOKUP)).thenReturn(Mono.just(Arrays.asList(null,"4",session("another-session"))));
        assertEquals(HttpStatus.UNAUTHORIZED,run("/api/v1/users/profile",token(4,NOW.plusSeconds(60)),false).getResponse().getStatusCode());
        assertEquals(0,routed.get());
    }
    @Test void malformedSessionStateCannotAuthorizeEvenTheVersionExemptRefresh() {
        when(values.multiGet(LOOKUP)).thenReturn(Mono.just(Arrays.asList(null,"4","[] trailing")));
        assertEquals(HttpStatus.UNAUTHORIZED,run("/api/v1/auth/session/refresh",token(4,NOW.plusSeconds(60)),false).getResponse().getStatusCode());
        assertEquals(0,routed.get());
    }
    private static String session(String id) {
        return "[{\"sessionId\":\""+id+"\",\"purpose\":\"LOGIN\",\"absoluteExpiresAt\":\"2026-11-02T12:00:00Z\"}]";
    }
    private void stored(String blacklist,String version) {when(values.multiGet(LOOKUP)).thenReturn(Mono.just(Arrays.asList(blacklist,version,session(SID))));}
    private MockServerWebExchange run(String path,String token,boolean ws) {
        var exchange=request(path,token,ws);filter.filter(exchange,e->{routed.incrementAndGet();return Mono.empty();}).block();return exchange;
    }
    private MockServerWebExchange request(String path,String token,boolean ws) {
        var req=MockServerHttpRequest.get(path);if(token!=null)req.header(HttpHeaders.AUTHORIZATION,"Bearer "+token);
        if(ws)req.header("Upgrade","websocket");return MockServerWebExchange.from(req);
    }
    private String token(Number version,Instant expiry) {
        var jwt=Jwts.builder().setSubject(USER).claim("roles",List.of("CUSTOMER")).claim("sessionId",SID)
                .setIssuedAt(Date.from(NOW.minusSeconds(60))).setExpiration(Date.from(expiry));
        if(version!=null)jwt.claim("ev",version);
        return jwt.signWith(keys.getPrivate(),SignatureAlgorithm.RS256).compact();
    }
}
