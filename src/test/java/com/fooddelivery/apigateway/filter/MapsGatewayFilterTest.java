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
        var p=new MapsGatewayProperties();p.setEnabled(true);p.setClientKeySecret("ab".repeat(32));return p;
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
    MockServerWebExchange exchange(MockServerHttpRequest request, long processingMillis) {
        var e=exchange(request);
        Route route=e.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        e.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR,Route.async().id(route.getId()).uri(route.getUri())
                .predicate(x->true).metadata(route.getMetadata()).metadata(MapsGatewayFilter.PROCESSING_TIMEOUT,processingMillis).build());
        return e;
    }
    static Flux<org.springframework.core.io.buffer.DataBuffer> paced(int chunks, int size, Duration gap) {
        return Flux.interval(gap).take(chunks).map(i->org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance.wrap(new byte[size]));
    }
    static org.springframework.cloud.gateway.filter.GatewayFilterChain consume(Duration processing, AtomicLong received) {
        return x->DataBufferUtils.join(x.getRequest().getBody()).doOnNext(b->{received.set(b.readableByteCount());DataBufferUtils.release(b);})
                .then(Mono.delay(processing)).then(Mono.fromRunnable(()->x.getResponse().setStatusCode(HttpStatus.NO_CONTENT)));
    }
    /** A body is bounded by progress, not a fixed total, and the route budget starts at the end of the body. Separate
     *  from the fixed-cutoff test above, which keeps covering a body that never sends a byte. */
    @Test void aSteadyUploadLongerThanTheOldCutoffReachesTheEdgeAndProcessingStartsAfterIt() {
        var filter=new MapsGatewayFilter(configured(),PEER);
        var received=new AtomicLong();
        // 7 x 160 KiB over ~3.5 s, then 2 s of processing: 5.5 s in all, beyond the old 2 s upload and 3 s response.
        var steady=exchange(MockServerHttpRequest.post("/api/v1/areas").header("Transfer-Encoding","chunked")
                .header("Origin","https://maps.test").body(paced(7,160*1024,Duration.ofMillis(500))),3000);
        filter.filter(steady,consume(Duration.ofSeconds(2),received)).block(Duration.ofSeconds(20));
        assertEquals(HttpStatus.NO_CONTENT,steady.getResponse().getStatusCode());
        assertEquals(7*160*1024,received.get());
    }
    @Test void anUploadBelowTheFloorIsRefusedAsAnUploadTimeout() {
        var filter=new MapsGatewayFilter(configured(),PEER);
        // One byte per 900 ms is never idle for 2 s but stays far below 128 KiB/s.
        var trickle=exchange(MockServerHttpRequest.post("/api/v1/areas").header("Transfer-Encoding","chunked")
                .header("Origin","https://maps.test").body(paced(6,1,Duration.ofMillis(900))));
        long started=System.nanoTime();
        filter.filter(trickle,consume(Duration.ZERO,new AtomicLong())).block(Duration.ofSeconds(20));
        assertEquals(HttpStatus.REQUEST_TIMEOUT,trickle.getResponse().getStatusCode());
        assertTrue(Duration.ofNanos(System.nanoTime()-started).compareTo(Duration.ofSeconds(4))<0,"refused at the first chunk below the floor");
    }
    @Test void processingBeyondTheRouteBudgetAfterTheBodyIsAGatewayTimeout() {
        var filter=new MapsGatewayFilter(configured(),PEER);
        var slow=exchange(MockServerHttpRequest.post("/api/v1/areas").header("Transfer-Encoding","chunked")
                .header("Origin","https://maps.test").body(paced(3,1024,Duration.ofMillis(400))),500);
        filter.filter(slow,consume(Duration.ofSeconds(2),new AtomicLong())).block(Duration.ofSeconds(20));
        assertEquals(HttpStatus.GATEWAY_TIMEOUT,slow.getResponse().getStatusCode());
        // The upload itself (1.2 s) is longer than this budget and was not charged to it.
        var fast=exchange(MockServerHttpRequest.post("/api/v1/areas").header("Transfer-Encoding","chunked")
                .header("Origin","https://maps.test").body(paced(3,1024,Duration.ofMillis(400))),500);
        filter.filter(fast,consume(Duration.ofMillis(100),new AtomicLong())).block(Duration.ofSeconds(20));
        assertEquals(HttpStatus.NO_CONTENT,fast.getResponse().getStatusCode());
    }
    /** P15-T015: an edge replica lost mid-exchange (SIGKILL) surfaced as Spring's default 500. Every transport loss
     *  before commit is a bounded, attributed 502; after commit the error propagates (the connection aborts); a
     *  non-transport fault is not relabelled as an upstream loss. */
    @Test void aLostUpstreamBeforeCommitIsABoundedBadGatewayAndNothingElseIs() {
        var filter=new MapsGatewayFilter(configured(),PEER);
        for(Throwable lost:List.<Throwable>of(new java.io.IOException(new java.net.SocketException("Connection reset")),
                new java.net.ConnectException("Connection refused"),reactor.netty.channel.AbortedException.beforeSend(),
                new RuntimeException(new java.io.IOException("wrapped")))) {
            var e=exchange(MockServerHttpRequest.post("/api/v1/areas").header("Transfer-Encoding","chunked")
                    .header("Origin","https://maps.test").body(paced(1,16,Duration.ofMillis(10))),3000);
            filter.filter(e,x->DataBufferUtils.join(x.getRequest().getBody()).doOnNext(DataBufferUtils::release).then(Mono.error(lost)))
                    .onErrorResume(escaped->Mono.empty()).block(Duration.ofSeconds(5)); // the status assertion decides
            assertEquals(HttpStatus.BAD_GATEWAY,e.getResponse().getStatusCode(),lost.toString());
            assertEquals("{\"code\":\"UPSTREAM_UNAVAILABLE\"}",e.getResponse().getBodyAsString().block(),lost.toString());
        }
        var committed=exchange(MockServerHttpRequest.get("/api/v1/areas").header("Origin","https://maps.test").build(),3000);
        var reset=new java.io.IOException("reset after commit");
        var afterCommit=assertThrows(RuntimeException.class,()->filter.filter(committed,x->x.getResponse().setComplete()
                .then(Mono.error(reset))).block(Duration.ofSeconds(5)));
        assertSame(reset,reactor.core.Exceptions.unwrap(afterCommit),"an error after commit propagates unchanged: "+afterCommit);
        var fault=exchange(MockServerHttpRequest.get("/api/v1/areas").header("Origin","https://maps.test").build(),3000);
        assertThrows(IllegalStateException.class,()->filter.filter(fault,x->Mono.error(new IllegalStateException("bug"))).block(Duration.ofSeconds(5)));
    }
    @Test void concurrentUploadsAreCappedPerReplicaAndReleasedWhenTheBodyEnds() {
        var properties=configured();properties.setConcurrentUploads(1);
        var filter=new MapsGatewayFilter(properties,PEER);
        var held=exchange(MockServerHttpRequest.post("/api/v1/areas").header("Transfer-Encoding","chunked")
                .header("Origin","https://maps.test").body(paced(4,1024,Duration.ofMillis(300))));
        var running=filter.filter(held,consume(Duration.ZERO,new AtomicLong())).subscribe();
        var second=exchange(MockServerHttpRequest.post("/api/v1/areas").header("Transfer-Encoding","chunked")
                .header("Origin","https://maps.test").remoteAddress(new InetSocketAddress("192.0.2.9",1)).body(paced(1,1,Duration.ofMillis(10))));
        filter.filter(second,consume(Duration.ZERO,new AtomicLong())).block(Duration.ofSeconds(5));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,second.getResponse().getStatusCode());
        Mono.delay(Duration.ofMillis(1800)).block();
        assertTrue(running.isDisposed()||held.getResponse().getStatusCode()!=null);
        var third=exchange(MockServerHttpRequest.post("/api/v1/areas").header("Transfer-Encoding","chunked")
                .header("Origin","https://maps.test").remoteAddress(new InetSocketAddress("192.0.2.10",1)).body(paced(1,1,Duration.ofMillis(10))));
        filter.filter(third,consume(Duration.ZERO,new AtomicLong())).block(Duration.ofSeconds(5));
        assertEquals(HttpStatus.NO_CONTENT,third.getResponse().getStatusCode(),"the finished upload released its slot");
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
    static String hmac(String secretHex,String client) throws Exception {
        var mac=javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(java.util.HexFormat.of().parseHex(secretHex),"HmacSHA256"));
        return java.util.HexFormat.of().formatHex(mac.doFinal(client.getBytes(StandardCharsets.UTF_8)));
    }
    MockServerWebExchange from(MockServerHttpRequest.BaseBuilder<?> builder,String address){
        return exchange(builder.remoteAddress(new InetSocketAddress(address,443)).header(MapsGatewayFilter.CLIENT_HEADER,"f".repeat(64)).build());
    }
    @Test void edgeRequestsCarryOnlyTheKeyedClientPseudonymAndOtherBackendsNone() throws Exception {
        var seen=new java.util.ArrayList<String>();
        // Two filter instances stand for two gateway replicas sharing the configured key.
        for(var filter:List.of(new MapsGatewayFilter(configured(),PEER),new MapsGatewayFilter(configured(),PEER))){
            for(var request:List.<MockServerHttpRequest.BaseBuilder<?>>of(MockServerHttpRequest.post("/api/v1/routes/calculate"),
                    MockServerHttpRequest.post("/maps-service/api/v1/routes/matrix"),MockServerHttpRequest.get("/api/v1/maps-session/session"),
                    MockServerHttpRequest.post("/api/v1/editor-routes/optimise").header(HttpHeaders.COOKIE,"maps=opaque"))){
                var e=from(request,"198.51.100.7");
                filter.filter(e,x->{seen.add(x.getRequest().getHeaders().getFirst(MapsGatewayFilter.CLIENT_HEADER));
                    assertEquals(1,x.getRequest().getHeaders().getOrEmpty(MapsGatewayFilter.CLIENT_HEADER).size());return Mono.empty();}).block();
                assertNull(e.getResponse().getStatusCode());
            }
        }
        assertEquals(8,seen.size());
        // The value is HMAC-SHA256 of the client bucket key, identical across replicas and never the address itself.
        assertEquals(java.util.Set.of(hmac("ab".repeat(32),"198.51.100.7")),new java.util.HashSet<>(seen));
        var other=new java.util.ArrayList<String>();
        new MapsGatewayFilter(configured(),PEER).filter(from(MockServerHttpRequest.post("/api/v1/routes/calculate"),"198.51.100.8"),
                x->{other.add(x.getRequest().getHeaders().getFirst(MapsGatewayFilter.CLIENT_HEADER));return Mono.empty();}).block();
        assertEquals(List.of(hmac("ab".repeat(32),"198.51.100.8")),other);
        // An IPv6 customer's /64 is one client, so rotation inside it cannot mint fresh edge budgets.
        var v6=new java.util.HashSet<String>();
        for(String address:List.of("2001:db8:1:2::1","2001:db8:1:2:ffff::9")) new MapsGatewayFilter(configured(),PEER).filter(
                from(MockServerHttpRequest.post("/api/v1/routes/calculate"),address),x->{v6.add(x.getRequest().getHeaders().getFirst(MapsGatewayFilter.CLIENT_HEADER));return Mono.empty();}).block();
        assertEquals(java.util.Set.of(hmac("ab".repeat(32),"20010db800010002")),v6);
        // Postal, public and asset backends never receive the header, even one a client supplied.
        String hash="a".repeat(64);
        for(String path:List.of("/api/v1/search","/public/"+hash+"/basemap.json","/assets/"+hash+"/release.json")){
            var e=from(MockServerHttpRequest.get(path),"198.51.100.7");
            new MapsGatewayFilter(configured(),PEER).filter(e,x->{assertNull(x.getRequest().getHeaders().getFirst(MapsGatewayFilter.CLIENT_HEADER),path);return Mono.empty();}).block();
            assertNull(e.getResponse().getStatusCode(),path);
        }
    }
    @Test void anEdgeRequestWithoutAUsableClientKeyIsRefusedBeforeForwarding() {
        for(String secret:java.util.Arrays.asList(null,"short")){
            var p=configured();p.setClientKeySecret(secret);
            var e=from(MockServerHttpRequest.post("/api/v1/routes/calculate"),"198.51.100.7");
            new MapsGatewayFilter(p,PEER).filter(e,x->{fail("forwarded without a client pseudonym");return Mono.empty();}).block();
            assertEquals(HttpStatus.SERVICE_UNAVAILABLE,e.getResponse().getStatusCode());
            assertEquals("{\"code\":\"MAPS_ADMISSION_UNAVAILABLE\"}",e.getResponse().getBodyAsString().block());
        }
    }
    @Test void editorRouteOperationsKeepTheSessionAndTheirPublicEnvelope() {
        for(String prefix:List.of("","/maps-service")) for(var entry:java.util.Map.of("calculate",4096,"directions",4096,"matrix",1048576,"match",1048576,"isochrones",1048576,"optimise",1048576,"elevation",1048576).entrySet()) {
            for(boolean declared:new boolean[]{true,false}) for(int size:new int[]{entry.getValue(),entry.getValue()+1}) {
                var builder=MockServerHttpRequest.post(prefix+"/api/v1/editor-routes/"+entry.getKey()).header(HttpHeaders.COOKIE,"maps=opaque").header("X-CSRF-Token","proof");
                if(declared)builder.header(HttpHeaders.CONTENT_LENGTH,Integer.toString(size));else builder.header(HttpHeaders.TRANSFER_ENCODING,"chunked");
                var e=exchange(builder.body(Flux.just(org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance.wrap(new byte[size]))));
                var count=new AtomicInteger();
                new MapsGatewayFilter(configured(),PEER).filter(e,clean->{
                    assertEquals("maps=opaque",clean.getRequest().getHeaders().getFirst(HttpHeaders.COOKIE));assertEquals("proof",clean.getRequest().getHeaders().getFirst("X-CSRF-Token"));
                    return DataBufferUtils.join(clean.getRequest().getBody()).doOnNext(buffer->{count.set(buffer.readableByteCount());DataBufferUtils.release(buffer);}).then();
                }).block();
                if(size==entry.getValue()){assertNull(e.getResponse().getStatusCode(),entry.getKey());assertEquals(size,count.get());}
                else {assertEquals(HttpStatus.PAYLOAD_TOO_LARGE,e.getResponse().getStatusCode(),entry.getKey());assertEquals(0,count.get());}
            }
            var bearer=exchange(MockServerHttpRequest.post(prefix+"/api/v1/editor-routes/"+entry.getKey()).header(HttpHeaders.AUTHORIZATION,"Bearer "+"a".repeat(64)).build());
            new MapsGatewayFilter(configured(),PEER).filter(bearer,x->{fail("editor route accepted a bearer credential");return Mono.empty();}).block();
            assertEquals(HttpStatus.BAD_REQUEST,bearer.getResponse().getStatusCode());
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
        var p=configured();p.setPublicOrigin("https://maps.test");p.setEdgeUri("https://e.test");p.setPublicUri("https://p.test");p.setAssetsUri("https://a.test");p.setPostalUri("https://c.test");
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

    // Product decision, 25 November 2026: compressed request bodies are not supported at Maps ingress.
    @Test void compressedRequestBodiesAreRefusedBeforeAnyByteIsReadOrForwarded() {
        var buffers = org.springframework.core.io.buffer.DefaultDataBufferFactory.sharedInstance;
        var routes = List.of(java.util.Map.entry(HttpMethod.POST, "/api/v1/areas"),
                java.util.Map.entry(HttpMethod.PUT, "/api/v1/metadata/records/11111111-1111-4111-8111-111111111111"),
                java.util.Map.entry(HttpMethod.POST, "/api/v1/saved-routes/11111111-1111-4111-8111-111111111111/annotations"),
                java.util.Map.entry(HttpMethod.POST, "/api/v1/spatial/relations"));
        for (var route : routes) for (String encoding : List.of("gzip", "br", "deflate", "identity")) {
            var subscribed = new AtomicInteger();
            var request = exchange(MockServerHttpRequest.method(route.getKey(), route.getValue())
                    .header(HttpHeaders.CONTENT_ENCODING, encoding).header(HttpHeaders.TRANSFER_ENCODING, "chunked")
                    .header(HttpHeaders.COOKIE, "maps=opaque").header("X-CSRF-Token", "fixture-proof").header("Idempotency-Key", "fixture-key")
                    .body(Flux.defer(() -> { subscribed.incrementAndGet(); return Flux.just(buffers.wrap(new byte[16])); })));
            new MapsGatewayFilter(configured(), PEER).filter(request, x -> { fail("encoded body was forwarded: " + encoding); return Mono.empty(); }).block();
            String where = route.getValue() + " " + encoding;
            assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, request.getResponse().getStatusCode(), where);
            assertTrue(request.getResponse().getBodyAsString().block().contains("REQUEST_ENCODING_REFUSED"), where);
            assertEquals(0, subscribed.get(), where);
        }
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
