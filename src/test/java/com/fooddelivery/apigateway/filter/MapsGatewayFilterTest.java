package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.config.MapsGatewayProperties;
import com.fooddelivery.apigateway.config.RateLimiterConfig;
import com.fooddelivery.apigateway.security.MapsRoutes;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;

class MapsGatewayFilterTest {
    static final java.util.function.Function<org.springframework.http.server.reactive.ServerHttpRequest,String> PEER=
            r->r.getRemoteAddress()==null?"unknown":r.getRemoteAddress().getAddress().getHostAddress();
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
    @Test void privateResponseCachePolicyIsCanonicalAfterTheDownstreamAppendsHeaders() {
        for(String prefix:List.of("","/maps-service")) for(String path:List.of("/api/v1/maps-session/session","/api/v1/areas/overlay/0/0/0","/api/v1/resources/11111111-1111-4111-8111-111111111111")) {
            var exchange=exchange(MockServerHttpRequest.get(prefix+path).build());
            new MapsGatewayFilter(configured(),PEER).filter(exchange,downstream->{
                downstream.getResponse().getHeaders().add(HttpHeaders.CACHE_CONTROL,"private, no-store");
                downstream.getResponse().getHeaders().add(HttpHeaders.CACHE_CONTROL,"public, max-age=600");
                downstream.getResponse().getHeaders().add(HttpHeaders.VARY,"Origin, Accept-Encoding, cookie");
                return downstream.getResponse().setComplete();
            }).block();
            assertEquals(List.of("private, no-store"),exchange.getResponse().getHeaders().get(HttpHeaders.CACHE_CONTROL),"Private response policy must be one canonical final value");
            assertEquals(java.util.Set.of("origin","accept-encoding","cookie","authorization"),new java.util.HashSet<>(exchange.getResponse().getHeaders().getVary().stream().map(String::toLowerCase).toList()));
        }
        var wildcard=exchange(MockServerHttpRequest.get("/api/v1/areas/overlay/0/0/0").build());
        new MapsGatewayFilter(configured(),PEER).filter(wildcard,downstream->{downstream.getResponse().getHeaders().setVary(List.of("*"));return downstream.getResponse().setComplete();}).block();
        assertEquals(List.of("*"),wildcard.getResponse().getHeaders().getVary());
        var publicMap=exchange(MockServerHttpRequest.get("/public/"+"a".repeat(64)+"/basemap.json").build());
        new MapsGatewayFilter(configured(),PEER).filter(publicMap,downstream->{downstream.getResponse().getHeaders().setCacheControl("public, max-age=600");return downstream.getResponse().setComplete();}).block();
        assertEquals("public, max-age=600",publicMap.getResponse().getHeaders().getCacheControl());
        var ordinary=exchange(MockServerHttpRequest.get("/unrelated-food-delivery-path").build());
        new MapsGatewayFilter(new MapsGatewayProperties(),PEER).filter(ordinary,downstream->{downstream.getResponse().getHeaders().setCacheControl("max-age=60");return downstream.getResponse().setComplete();}).block();
        assertEquals("max-age=60",ordinary.getResponse().getHeaders().getCacheControl());
    }
    @Test void publicIncidentalCredentialsNeverEnterLegacyAuthenticationAndPreserveAssetTransport() {
        var filter=new MapsGatewayFilter(configured(),PEER);var legacy=new GlobalJwtAuthFilter();var forwarded=new AtomicInteger();
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
        var filter=new MapsGatewayFilter(configured(),PEER);var legacy=new GlobalJwtAuthFilter();var count=new AtomicInteger();
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
    @Test void machineJobExecutionForwardsOneBearerOnItsExactPostPath() {
        String path="/api/v1/machine/resource-jobs/11111111-1111-4111-8111-111111111111/execute";
        String credential="Bearer "+"a".repeat(64);
        var filter=new MapsGatewayFilter(configured(),PEER);
        var legacy=new GlobalJwtAuthFilter();
        for(String prefix:List.of("","/maps-service")){
            var valid=exchange(MockServerHttpRequest.post(prefix+path).header(HttpHeaders.AUTHORIZATION,credential)
                    .header("X-User-Id","spoofed").build());
            filter.filter(valid,x->legacy.filter(x,clean->{
                assertEquals(List.of(credential),clean.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION));
                assertNull(clean.getRequest().getHeaders().getFirst("X-User-Id"));
                return clean.getResponse().setComplete();
            })).block();
            assertNull(valid.getResponse().getStatusCode());
            assertEquals("private, no-store",valid.getResponse().getHeaders().getCacheControl());
        }
        var missing=exchange(MockServerHttpRequest.post(path).build());
        var duplicate=exchange(MockServerHttpRequest.post(path).header(HttpHeaders.AUTHORIZATION,credential,credential).build());
        var cookie=exchange(MockServerHttpRequest.post(path).header(HttpHeaders.AUTHORIZATION,credential).header(HttpHeaders.COOKIE,"session=opaque").build());
        var origin=exchange(MockServerHttpRequest.post(path).header(HttpHeaders.AUTHORIZATION,credential).header(HttpHeaders.ORIGIN,"https://maps.test").build());
        var csrf=exchange(MockServerHttpRequest.post(path).header(HttpHeaders.AUTHORIZATION,credential).header("X-CSRF-Token","opaque").build());
        var body=exchange(MockServerHttpRequest.post(path).header(HttpHeaders.AUTHORIZATION,credential).header(HttpHeaders.CONTENT_LENGTH,"1").body("x"));
        var get=exchange(MockServerHttpRequest.get(path).header(HttpHeaders.AUTHORIZATION,credential).build());
        var person=exchange(MockServerHttpRequest.post(path.replace("/machine","")).header(HttpHeaders.AUTHORIZATION,credential).build());
        for(var refusal:java.util.Map.of(missing,HttpStatus.UNAUTHORIZED,duplicate,HttpStatus.UNAUTHORIZED,cookie,HttpStatus.BAD_REQUEST,
                origin,HttpStatus.BAD_REQUEST,csrf,HttpStatus.BAD_REQUEST,body,HttpStatus.PAYLOAD_TOO_LARGE,get,HttpStatus.METHOD_NOT_ALLOWED,person,HttpStatus.BAD_REQUEST).entrySet()){
            filter.filter(refusal.getKey(),x->{fail("refused worker request was forwarded");return Mono.empty();}).block();
            assertEquals(refusal.getValue(),refusal.getKey().getResponse().getStatusCode());
        }
    }

    @Test void unknownInternalEncodedAndMixedCredentialsFailBeforeForwarding() {
        var filter=new MapsGatewayFilter(configured(),PEER);
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
        new MapsGatewayFilter(new MapsGatewayProperties(),PEER).filter(disabled,x->{fail("disabled adapter forwarded");return Mono.empty();}).block();
        assertEquals(HttpStatus.NOT_FOUND,disabled.getResponse().getStatusCode());
    }
    @Test void canonicalAliasesAndSeparatePopulationsRetainPartitionedReplicaCap() {
        var properties=configured();properties.setMaximumReplicas(2);properties.setPrivateRequestsPerSecond(4);properties.setPublicRequestsPerSecond(4);
        var time=new AtomicLong(1);var first=new MapsGatewayFilter(properties,PEER,time::get);var second=new MapsGatewayFilter(properties,PEER,time::get);
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
        var filter=new MapsGatewayFilter(configured(),PEER);
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
    @Test void routeBodiesShareTheRoutingDecoderBoundaryForDeclaredAndStreamedLengths() {
        for (String operation : List.of("calculate", "directions")) for (String prefix : List.of("", "/maps-service")) {
            String path = prefix + "/api/v1/routes/" + operation;
            for (int size : new int[]{4096,4097}) for (boolean declared : new boolean[]{true,false}) {
                var builder = MockServerHttpRequest.post(path);
                if (declared) builder.header(HttpHeaders.CONTENT_LENGTH, Integer.toString(size));
                else builder.header(HttpHeaders.TRANSFER_ENCODING, "chunked");
                var e = exchange(builder.body(Flux.just(org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance.wrap(new byte[size]))));
                var bytes = new AtomicInteger();
                new MapsGatewayFilter(configured(),PEER).filter(e,x->DataBufferUtils.join(x.getRequest().getBody())
                        .doOnNext(buffer->{bytes.set(buffer.readableByteCount());DataBufferUtils.release(buffer);}).then()).block();
                if (size == 4096) { assertNull(e.getResponse().getStatusCode(),path);assertEquals(size,bytes.get()); }
                else { assertEquals(HttpStatus.PAYLOAD_TOO_LARGE,e.getResponse().getStatusCode(),path);assertEquals(0,bytes.get()); }
            }
        }
    }
    @Test void boundedAnalysesUseTheirOwnBodyLimitAndStripAccountHeaders(){
        for(String prefix:List.of("","/maps-service")) for(String operation:List.of("matrix","isochrones","match","optimise","elevation")) {
            for(boolean declared:new boolean[]{true,false}) for(int size:new int[]{1048576,1048577}) {
                var builder=MockServerHttpRequest.post(prefix+"/api/v1/routes/"+operation).header("Cookie","private-canary").header("Authorization","Bearer private-canary").header("X-CSRF-Token","private-canary");
                if(declared)builder.header(HttpHeaders.CONTENT_LENGTH,Integer.toString(size));else builder.header(HttpHeaders.TRANSFER_ENCODING,"chunked");
                var exchange=exchange(builder.body(Flux.just(org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance.wrap(new byte[size]))));
                var count=new AtomicInteger();
                new MapsGatewayFilter(configured(),PEER).filter(exchange,clean->{
                    assertNull(clean.getRequest().getHeaders().getFirst("Cookie"));assertNull(clean.getRequest().getHeaders().getFirst("Authorization"));assertNull(clean.getRequest().getHeaders().getFirst("X-CSRF-Token"));
                    return DataBufferUtils.join(clean.getRequest().getBody()).doOnNext(buffer->{count.set(buffer.readableByteCount());DataBufferUtils.release(buffer);}).then();
                }).block();
                if(size==1048576){assertNull(exchange.getResponse().getStatusCode(),"Analysis body refused below owner limit");assertEquals(size,count.get());}
                else {assertEquals(HttpStatus.PAYLOAD_TOO_LARGE,exchange.getResponse().getStatusCode());assertEquals(0,count.get());}
            }
        }
    }
    @Test void declaredEncodedFontStackRemainsUsableWithoutOpeningEncodedPathAliases(){
        var filter=new MapsGatewayFilter(configured(),PEER);
        var e=exchange(MockServerHttpRequest.method(org.springframework.http.HttpMethod.GET,java.net.URI.create("https://maps.test/assets/"+"a".repeat(64)+"/glyphs/Noto%20Sans%20Regular%2CNoto%20Sans%20Devanagari%20Regular%2CNoto%20Sans%20Kannada%20Regular/0-255.pbf")).build());
        var count=new AtomicInteger();filter.filter(e,x->{assertTrue(MapsGatewayFilter.admitted(x));count.incrementAndGet();return Mono.empty();}).block();assertEquals(1,count.get());
    }
    HttpStatusCode call(MapsGatewayFilter filter, MockServerHttpRequest.BaseBuilder<?> request, String address) {
        var e=exchange(request.remoteAddress(new InetSocketAddress(address,4444)).build());
        filter.filter(e,x->Mono.empty()).block();return e.getResponse().getStatusCode();
    }
    @Test void oneClientExhaustsOnlyItsOwnShareAndRefusalsDoNotSpendTheTotal() {
        var filter=new MapsGatewayFilter(configured(),PEER,new AtomicLong(1)::get);int admitted=0;
        for(int i=0;i<5000;i++)if(call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session"),"198.51.100.7")==null)admitted++;
        assertEquals(30,admitted);
        assertNull(call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session"),"203.0.113.8"),"another client was starved");
    }
    @Test void clientsBehindTheTrustedProxyAreSeparateAndCannotPickTheirBucket() {
        var filter=new MapsGatewayFilter(configured(),new RateLimiterConfig(List.of("172.18.0.0/16"))::clientAddress,new AtomicLong(1)::get);
        for(int i=0;i<30;i++)assertNull(call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session").header("X-Forwarded-For","198.51.100.7"),"172.18.0.12"));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session").header("X-Forwarded-For","198.51.100.7"),"172.18.0.12"));
        assertNull(call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session").header("X-Forwarded-For","198.51.100.8"),"172.18.0.12"));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session").header("X-Forwarded-For","spoofed, 198.51.100.7"),"172.18.0.12"),
                "an earlier hop is the client's own text and must not move it to a new bucket");
    }
    @Test void rotatingWithinAnIpv6PrefixStaysInOneClientBucket() {
        var filter=new MapsGatewayFilter(configured(),PEER,new AtomicLong(1)::get);
        for(int i=0;i<30;i++)assertNull(call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session"),"2001:db8:1:2::"+Integer.toHexString(i+1)));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session"),"2001:db8:1:2::ff"));
        assertNull(call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session"),"2001:db8:1:3::1"));
        assertEquals("198.51.100.7",MapsGatewayFilter.clientKey("198.51.100.7"));
        assertEquals("::ffff:198.51.100.7",MapsGatewayFilter.clientKey("::ffff:198.51.100.7"),"IPv4-mapped clients must not share a zero prefix");
    }
    @Test void aPrivateResourceFloodCannotStopSessionLifecycle() {
        var filter=new MapsGatewayFilter(configured(),PEER,new AtomicLong(1)::get);
        for(int i=0;i<300;i++)call(filter,MockServerHttpRequest.get("/api/v1/resources"),"198.51."+(i/250)+"."+(i%250));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,call(filter,MockServerHttpRequest.get("/api/v1/resources"),"203.0.113.9"),"setup: private population must be exhausted");
        assertNull(call(filter,MockServerHttpRequest.post("/api/v1/maps-session/logout"),"203.0.113.9"));
        assertNull(call(filter,MockServerHttpRequest.get("/api/v1/maps-session/session"),"203.0.113.9"));
    }
    @Test void signInIsLimitedPerClientPerHourAcrossPhoneRotation() {
        var time=new AtomicLong(1);var filter=new MapsGatewayFilter(configured(),PEER,time::get);
        for(int i=0;i<30;i++){time.addAndGet(1_000_000_000L);assertNull(call(filter,MockServerHttpRequest.post(i%2==0?"/api/v1/maps-session/otp":"/api/v1/maps-session/login"),"198.51.100.7"));}
        time.addAndGet(1_000_000_000L);
        var refused=exchange(MockServerHttpRequest.post("/api/v1/maps-session/otp").remoteAddress(new InetSocketAddress("198.51.100.7",4444)).build());
        filter.filter(refused,x->Mono.empty()).block();
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,refused.getResponse().getStatusCode());assertEquals("3600",refused.getResponse().getHeaders().getFirst("Retry-After"));
        assertNull(call(filter,MockServerHttpRequest.post("/api/v1/maps-session/otp"),"203.0.113.8"));
        assertNull(call(filter,MockServerHttpRequest.post("/api/v1/maps-session/logout"),"198.51.100.7"),"a sign-in limit must not block sign-out");
        time.addAndGet(3_600_000_000_000L);
        assertNull(call(filter,MockServerHttpRequest.post("/api/v1/maps-session/otp"),"198.51.100.7"));
    }
    @Test void clientShareMustBeBelowItsPopulationOrItCanNeverBite() {
        var p=configured();p.setPublicOrigin("https://maps.test");p.setEdgeUri("https://e.test");p.setPublicUri("https://p.test");p.setAssetsUri("https://a.test");p.setPostalUri("https://c.test");p.setRoutingUri("https://r.test");
        p.validate();
        p.setPrivateClientRequestsPerSecond(100);assertThrows(IllegalStateException.class,p::validate);p.setPrivateClientRequestsPerSecond(30);
        p.setPublicClientRequestsPerSecond(1000);assertThrows(IllegalStateException.class,p::validate);p.setPublicClientRequestsPerSecond(100);
        p.setSignInClientRequestsPerHour(0);assertThrows(IllegalStateException.class,p::validate);
    }
    @Test void savedAreaWritesKeepPrivateHeadersAndTheirExactBodyLimit() {
        final int limit = 10_000_000;
        String root = "/api/v1/areas", id = root + "/11111111-1111-4111-8111-111111111111";
        var buffers = org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance;
        for (var operation : List.of(java.util.Map.entry(HttpMethod.POST, root), java.util.Map.entry(HttpMethod.PUT, id),
                java.util.Map.entry(HttpMethod.POST, "/api/v1/area-editor/import"),
                java.util.Map.entry(HttpMethod.POST, id + "/repair"))) {
            var filter = new MapsGatewayFilter(configured(), PEER);
            var good = exchange(MockServerHttpRequest.method(operation.getKey(), operation.getValue())
                    .header(HttpHeaders.CONTENT_LENGTH, Integer.toString(limit)).header(HttpHeaders.COOKIE,"maps=opaque")
                    .header("X-CSRF-Token","fixture-proof").header("X-User-Id","forged").header("Idempotency-Key","fixture-key")
                    .body(Flux.just(buffers.wrap(new byte[limit]))));
            var received = new AtomicInteger();
            filter.filter(good, x -> {
                var h=x.getRequest().getHeaders();assertEquals("maps=opaque",h.getFirst(HttpHeaders.COOKIE));
                assertEquals("fixture-proof",h.getFirst("X-CSRF-Token"));assertEquals("fixture-key",h.getFirst("Idempotency-Key"));assertNull(h.getFirst("X-User-Id"));
                return DataBufferUtils.join(x.getRequest().getBody()).doOnNext(buffer->{received.set(buffer.readableByteCount());DataBufferUtils.release(buffer);}).then();
            }).block();
            assertNull(good.getResponse().getStatusCode(), operation.getValue());assertEquals(limit, received.get());
            var declared = exchange(MockServerHttpRequest.method(operation.getKey(), operation.getValue())
                    .header(HttpHeaders.CONTENT_LENGTH,Integer.toString(limit+1)).build());
            filter.filter(declared,x->{fail("oversize declared body entered private handler");return Mono.empty();}).block();
            assertEquals(HttpStatus.PAYLOAD_TOO_LARGE,declared.getResponse().getStatusCode());
            var streamed = exchange(MockServerHttpRequest.method(operation.getKey(), operation.getValue())
                    .header(HttpHeaders.TRANSFER_ENCODING,"chunked").body(Flux.just(buffers.wrap(new byte[limit+1]))));
            filter.filter(streamed,x->DataBufferUtils.join(x.getRequest().getBody()).doOnNext(DataBufferUtils::release).then()).block();
            assertEquals(HttpStatus.PAYLOAD_TOO_LARGE,streamed.getResponse().getStatusCode());
        }
        var filter = new MapsGatewayFilter(configured(), PEER);
        var mixed = exchange(MockServerHttpRequest.post(root).header(HttpHeaders.AUTHORIZATION,"Bearer fixture").build());
        filter.filter(mixed,x->{fail("mixed credentials reached private area handler");return Mono.empty();}).block();
        assertEquals(HttpStatus.BAD_REQUEST,mixed.getResponse().getStatusCode());
        var read = exchange(MockServerHttpRequest.method(HttpMethod.GET,id).header(HttpHeaders.CONTENT_LENGTH,"2").body("{}"));
        filter.filter(read,x->{fail("GET body reached private area handler");return Mono.empty();}).block();
        assertEquals(HttpStatus.BAD_REQUEST,read.getResponse().getStatusCode());
    }

    @Test void privateAreaMetadataUsesItsOwnByteBoundary() {
        for (String path : List.of("/api/v1/metadata/records/11111111-1111-4111-8111-111111111111", "/api/v1/road-metadata/records/11111111-1111-4111-8111-111111111111")) {
        var buffers = org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance;
        var filter = new MapsGatewayFilter(configured(), PEER);
        for (int size : new int[]{65_536,65_537}) {
            var request = exchange(MockServerHttpRequest.put(path).header(HttpHeaders.TRANSFER_ENCODING,"chunked")
                    .body(Flux.just(buffers.wrap(new byte[size]))));
            var received = new AtomicInteger();
            filter.filter(request, x->DataBufferUtils.join(x.getRequest().getBody())
                    .doOnNext(buffer->{received.set(buffer.readableByteCount());DataBufferUtils.release(buffer);}).then()).block();
            if (size == 65_536) {
                assertNull(request.getResponse().getStatusCode(), path);
                assertEquals(size, received.get());
            } else {
                assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, request.getResponse().getStatusCode(), path);
                assertEquals(0, received.get());
            }
        }
        }
    }

    @Test void privateDomainWritesUseTheirDeclaredEnvelopeLimits() {
        for (var item : java.util.Map.of("/api/v1/saved-routes/11111111-1111-4111-8111-111111111111/annotations",400_000,
                "/api/v1/spatial/relations",1_048_576).entrySet()) {
        String path = item.getKey();int limit = item.getValue();
        var buffers = org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance;
        var filter = new MapsGatewayFilter(configured(), PEER);
        for (int size : new int[]{limit,limit+1}) {
            var request = exchange(MockServerHttpRequest.post(path).header(HttpHeaders.TRANSFER_ENCODING,"chunked")
                    .body(Flux.just(buffers.wrap(new byte[size]))));
            var received = new AtomicInteger();
            filter.filter(request, x->DataBufferUtils.join(x.getRequest().getBody())
                    .doOnNext(buffer->{received.set(buffer.readableByteCount());DataBufferUtils.release(buffer);}).then()).block();
            if (size == limit) {
                assertNull(request.getResponse().getStatusCode(), path);
                assertEquals(size, received.get());
            } else {
                assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, request.getResponse().getStatusCode(), path);
                assertEquals(0, received.get());
            }
        }
        }
    }

    @Test void publicDiscoveryNeverForwardsPersonCredentials() {
        for(String path:List.of("search","reverse","pois","features/osm:node:101")) {
            var filter=new MapsGatewayFilter(configured(),PEER);var received=new AtomicInteger();
            var request=exchange(MockServerHttpRequest.get("/api/v1/"+path).header(HttpHeaders.AUTHORIZATION,"Bearer incidental").header(HttpHeaders.COOKIE,"__Host-maps-fixture=opaque").header("X-CSRF-Token","incidental").build());
            filter.filter(request,clean->{
                assertNull(clean.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION),path);
                assertNull(clean.getRequest().getHeaders().getFirst(HttpHeaders.COOKIE),path);
                assertNull(clean.getRequest().getHeaders().getFirst("X-CSRF-Token"),path);
                received.incrementAndGet();return Mono.empty();
            }).block();
            assertEquals(1,received.get(),path);assertNull(request.getResponse().getStatusCode(),path);
        }
    }

}
