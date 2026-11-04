package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.config.MapsGatewayProperties;
import com.fooddelivery.apigateway.security.MapsRoutes;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;

class MapsGatewayFilterTest {
    MapsGatewayProperties configured() {
        var p=new MapsGatewayProperties();p.setEnabled(true);return p;
    }
    MockServerWebExchange exchange(MockServerHttpRequest request) {
        var e=MockServerWebExchange.from(request);
        var policy=MapsRoutes.classify(request.getURI().getPath());
        if(policy!=null)e.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR,
                Route.async().id("maps-v1-"+policy.backend()).uri("https://internal.test")
                        .predicate(x->true).metadata("maps.contract","v1").metadata("maps.backend",policy.backend()).build());
        return e;
    }
    @Test void publicIncidentalCredentialsNeverEnterLegacyAuthenticationAndPreserveAssetTransport() {
        var filter=new MapsGatewayFilter(configured());var legacy=new GlobalJwtAuthFilter();var forwarded=new AtomicInteger();
        var e=exchange(MockServerHttpRequest.get("/public/"+"a".repeat(64)+"/basemap.pmtiles")
                .header(HttpHeaders.AUTHORIZATION,"Bearer expired").header(HttpHeaders.COOKIE,"old=expired")
                .header("X-Identity-Signature","formerly-valid").header("X-User-Id","spoofed")
                .header("Forwarded","host=evil.test;proto=http").header("X-Forwarded-For","attacker")
                .header("Range","bytes=0-16383").header("If-Range","\"immutable\"").header("Accept-Encoding","gzip").build());
        filter.filter(e,x->legacy.filter(x,clean->{
            assertNull(clean.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
            assertNull(clean.getRequest().getHeaders().getFirst(HttpHeaders.COOKIE));
            assertNull(clean.getRequest().getHeaders().getFirst("X-Identity-Signature"));
            assertNull(clean.getRequest().getHeaders().getFirst("X-User-Id"));
            assertNull(clean.getRequest().getHeaders().getFirst("Forwarded"));
            assertEquals("bytes=0-16383",clean.getRequest().getHeaders().getFirst("Range"));
            assertEquals("\"immutable\"",clean.getRequest().getHeaders().getFirst("If-Range"));
            assertEquals("gzip",clean.getRequest().getHeaders().getFirst("Accept-Encoding"));
            forwarded.incrementAndGet();return Mono.empty();
        })).block();
        assertEquals(1,forwarded.get());assertNull(e.getResponse().getHeaders().getCacheControl());
    }
    @Test void delegatedCookieRunsBeforeLegacySignatureAndOptionsExceptions() {
        var filter=new MapsGatewayFilter(configured());var legacy=new GlobalJwtAuthFilter();var count=new AtomicInteger();
        var e=exchange(MockServerHttpRequest.get("/api/v1/maps-session/session").header("Cookie","__Host-maps-fixture=opaque")
                .header("X-Identity-Signature","forged").header("X-User-Id","SERVICE").build());
        filter.filter(e,x->legacy.filter(x,clean->{
            assertEquals("__Host-maps-fixture=opaque",clean.getRequest().getHeaders().getFirst("Cookie"));
            assertNull(clean.getRequest().getHeaders().getFirst("X-User-Id"));count.incrementAndGet();return Mono.empty();
        })).block();assertEquals(1,count.get());assertEquals("no-store",e.getResponse().getHeaders().getCacheControl());
        var options=exchange(MockServerHttpRequest.options("/api/v1/maps-session/session").build());
        filter.filter(options,x->{fail("private preflight reached legacy OPTIONS bypass");return Mono.empty();}).block();
        assertEquals(HttpStatus.METHOD_NOT_ALLOWED,options.getResponse().getStatusCode());
    }
    @Test void unknownInternalEncodedAndMixedCredentialsFailBeforeForwarding() {
        var filter=new MapsGatewayFilter(configured());
        for(var request:new MockServerHttpRequest[]{
                MockServerHttpRequest.get("/maps-service/internal/maps/v1/validate").build(),
                MockServerHttpRequest.get("/identity-service/api/v1/auth/otp").build(),
                MockServerHttpRequest.get("/api/v1/maps-session/session?token=secret").build(),
                MockServerHttpRequest.get("/api/v1/maps-session/session").header("Authorization","Bearer token").build(),
                MockServerHttpRequest.get("/maps-service/api/v1/maps-session/%73ession").build()}){
            var e=exchange(request);filter.filter(e,x->{fail("refused Maps request was forwarded");return Mono.empty();}).block();
            assertNotNull(e.getResponse().getStatusCode());assertTrue(e.getResponse().getStatusCode().is4xxClientError());
        }
        var disabled=exchange(MockServerHttpRequest.get("/api/v1/maps-session/session").build());
        new MapsGatewayFilter(new MapsGatewayProperties()).filter(disabled,x->{fail("disabled adapter forwarded");return Mono.empty();}).block();
        assertEquals(HttpStatus.NOT_FOUND,disabled.getResponse().getStatusCode());
    }
    @Test void canonicalAliasesAndSeparatePopulationsRetainPartitionedReplicaCap() {
        var properties=configured();properties.setMaximumReplicas(2);properties.setPrivateRequestsPerSecond(4);properties.setPublicRequestsPerSecond(4);
        var time=new AtomicLong(1);var first=new MapsGatewayFilter(properties,time::get);var second=new MapsGatewayFilter(properties,time::get);
        for(var filter:new MapsGatewayFilter[]{first,second}){
            for(String path:new String[]{"/api/v1/maps-session/session","/maps-service/api/v1/maps-session/session"}){
                var e=exchange(MockServerHttpRequest.get(path).build());filter.filter(e,x->Mono.empty()).block();assertNull(e.getResponse().getStatusCode());
            }
            var exhausted=exchange(MockServerHttpRequest.get("/api/v1/maps-session/session").build());filter.filter(exhausted,x->Mono.empty()).block();
            assertEquals(HttpStatus.TOO_MANY_REQUESTS,exhausted.getResponse().getStatusCode());
            var publicRequest=exchange(MockServerHttpRequest.get("/public/"+"a".repeat(64)+"/schema.json").build());
            filter.filter(publicRequest,x->Mono.empty()).block();assertNull(publicRequest.getResponse().getStatusCode());
        }
        time.addAndGet(1_000_000_000L);var recovered=exchange(MockServerHttpRequest.get("/api/v1/maps-session/session").build());
        first.filter(recovered,x->Mono.empty()).block();assertNull(recovered.getResponse().getStatusCode());
    }
    @Test void chunkedBodySizeAndSlowUploadAreBoundedWhileStreamingExactBytes() {
        var filter=new MapsGatewayFilter(configured());
        var oversized=exchange(MockServerHttpRequest.post("/api/v1/maps-session/login").header("Transfer-Encoding","chunked")
                .body(Flux.just(org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance.wrap(new byte[8193]))));
        filter.filter(oversized,x->DataBufferUtils.join(x.getRequest().getBody()).doOnNext(DataBufferUtils::release).then()).block();
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE,oversized.getResponse().getStatusCode());
        var slow=exchange(MockServerHttpRequest.post("/api/v1/maps-session/login").header("Transfer-Encoding","chunked")
                .body(Flux.never()));long started=System.nanoTime();
        filter.filter(slow,x->DataBufferUtils.join(x.getRequest().getBody()).doOnNext(DataBufferUtils::release).then()).block();
        assertEquals(HttpStatus.REQUEST_TIMEOUT,slow.getResponse().getStatusCode());
        assertTrue(Duration.ofNanos(System.nanoTime()-started).compareTo(Duration.ofSeconds(3))<0);
    }
    @Test void declaredEncodedFontStackRemainsUsableWithoutOpeningEncodedPathAliases(){
        var filter=new MapsGatewayFilter(configured());
        var e=exchange(MockServerHttpRequest.method(org.springframework.http.HttpMethod.GET,java.net.URI.create("https://maps.test/assets/"+"a".repeat(64)+"/glyphs/Noto%20Sans%20Regular%2CNoto%20Sans%20Devanagari%20Regular%2CNoto%20Sans%20Kannada%20Regular/0-255.pbf")).build());
        var count=new AtomicInteger();filter.filter(e,x->{assertTrue(MapsGatewayFilter.admitted(x));count.incrementAndGet();return Mono.empty();}).block();assertEquals(1,count.get());
    }
}
