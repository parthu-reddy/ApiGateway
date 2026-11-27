package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.config.MapsGatewayProperties;
import com.fooddelivery.apigateway.security.MapsRoutes;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.nio.charset.StandardCharsets;
import io.netty.util.NetUtil;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;
import java.util.concurrent.atomic.AtomicBoolean;
import static net.logstash.logback.argument.StructuredArguments.kv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Exact Maps policy precedes OPTIONS/legacy signed-header/query bearer handling. */
public final class MapsGatewayFilter implements GlobalFilter, Ordered {
    private static final String ADMITTED = MapsGatewayFilter.class.getName()+".admitted";
    private final MapsGatewayProperties properties;
    private final LongSupplier monotonic;
    private final ConcurrentHashMap<String,Bucket> totals = new ConcurrentHashMap<>();
    private final Cache<String,Bucket> peers = Caffeine.newBuilder().maximumSize(10000).expireAfterAccess(Duration.ofMinutes(2)).build();
    private final Cache<String,Bucket> signIns = Caffeine.newBuilder().maximumSize(10000).expireAfterAccess(Duration.ofHours(2)).build();
    private final Function<ServerHttpRequest,String> clientAddress;
    private static final long SECOND = 1_000_000_000L, HOUR = 3600*SECOND;
    /** Route metadata: the route's processing budget in milliseconds, counted from the end of the request body. */
    public static final String PROCESSING_TIMEOUT = "maps.processing-timeout";
    static final Duration UPLOAD_IDLE = Duration.ofSeconds(2);
    /** Bytes per second: a 10 MB area body may take about 78 s, a 64 KiB note about 2.5 s. */
    static final long UPLOAD_FLOOR = 128 * 1024;
    private final java.util.concurrent.atomic.AtomicInteger uploads = new java.util.concurrent.atomic.AtomicInteger();
    private static final class Bucket {
        long start; int used; boolean initialized;
        synchronized boolean take(long now, int limit, long window) {
            if (!initialized||now-start>=window) {start=now;used=0;initialized=true;}
            if(used>=limit)return false;used++;return true;
        }
    }
    public MapsGatewayFilter(MapsGatewayProperties properties, Function<ServerHttpRequest,String> clientAddress) { this(properties,clientAddress,System::nanoTime); }
    public MapsGatewayFilter(MapsGatewayProperties properties, Function<ServerHttpRequest,String> clientAddress, LongSupplier monotonic) { this.properties=properties;this.clientAddress=clientAddress;this.monotonic=monotonic; }
    /** One IPv6 customer holds a whole /64, so rotating within it must not mint new client buckets. */
    static String clientKey(String address) {
        byte[] raw=NetUtil.createByteArrayFromIpAddressString(address);
        if(raw==null||raw.length!=16||Arrays.equals(Arrays.copyOf(raw,8),new byte[8]))return address;
        return HexFormat.of().formatHex(raw,0,8);
    }
    /** The edge's heavy-operation budget key: a keyed pseudonym of clientKey, so no address reaches the edge. */
    public static final String CLIENT_HEADER = "X-Maps-Client";
    private javax.crypto.spec.SecretKeySpec pseudonymKey;
    private String pseudonym(String client) {
        try {
            if (pseudonymKey == null) {
                if (!properties.clientKeySecretValid()) return null;
                pseudonymKey = new javax.crypto.spec.SecretKeySpec(HexFormat.of().parseHex(properties.getClientKeySecret()), "HmacSHA256");
            }
            var mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(pseudonymKey);
            return HexFormat.of().formatHex(mac.doFinal(client.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException unavailable) { return null; }
    }
    public static boolean admitted(ServerWebExchange exchange) { return Boolean.TRUE.equals(exchange.getAttribute(ADMITTED)); }
    private static Mono<Void> refuse(ServerWebExchange exchange, String retryAfter) {
        exchange.getResponse().getHeaders().set("Retry-After",retryAfter);return fail(exchange,HttpStatus.TOO_MANY_REQUESTS,"ADMISSION_EXCEEDED");
    }
    @Override public int getOrder() { return -100; }
    @Override public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path=exchange.getRequest().getURI().getPath();
        var policy=MapsRoutes.classify(path);
        if(policy==null&&!MapsRoutes.reserved(path)) {
            if(properties.isEnabled())return fail(exchange,HttpStatus.NOT_FOUND,"MAPS_ROUTE_UNAVAILABLE");
            return chain.filter(exchange);
        }
        Route route=exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if(!properties.isEnabled()||policy==null||route==null||!"v1".equals(route.getMetadata().get("maps.contract"))
                ||!policy.backend().equals(route.getMetadata().get("maps.backend")))return fail(exchange,HttpStatus.NOT_FOUND,"MAPS_ROUTE_UNAVAILABLE");
        String raw=exchange.getRequest().getURI().getRawPath();
        boolean encodedGlyph=policy.operation().equals("map-glyph")&&raw.replaceAll("(?i)%20|%2c", "").indexOf('%')<0;
        if(raw.contains("%")&&!encodedGlyph||path.contains("//")||path.contains("/./")||path.contains("/../")||path.endsWith("/.."))
            return fail(exchange,HttpStatus.BAD_REQUEST,"INVALID_PATH");
        for(String key:exchange.getRequest().getQueryParams().keySet())
            if(List.of("token","access_token","id_token","credential","authorization").contains(key.toLowerCase(Locale.ROOT)))
                return fail(exchange,HttpStatus.BAD_REQUEST,"URL_CREDENTIAL_REFUSED");
        if(!policy.methods().contains(exchange.getRequest().getMethod()))return fail(exchange,HttpStatus.METHOD_NOT_ALLOWED,"METHOD_NOT_ALLOWED");
        var method=exchange.getRequest().getMethod();
        String operation=policy.operation();
        boolean machine=operation.equals("machine-job-execute");
        var requestHeaders=exchange.getRequest().getHeaders();
        if(machine) {
            if(requestHeaders.containsKey(HttpHeaders.COOKIE)||requestHeaders.containsKey(HttpHeaders.ORIGIN)||requestHeaders.containsKey("X-CSRF-Token"))
                return fail(exchange,HttpStatus.BAD_REQUEST,"MIXED_CREDENTIAL_REFUSED");
            var credentials=requestHeaders.getOrEmpty(HttpHeaders.AUTHORIZATION);
            if(credentials.size()!=1||!credentials.getFirst().matches("Bearer [0-9a-f]{64}"))
                return fail(exchange,HttpStatus.UNAUTHORIZED,"INVALID_MACHINE_CREDENTIAL");
        } else if(!policy.publicRoute()&&requestHeaders.containsKey(HttpHeaders.AUTHORIZATION)) {
            return fail(exchange,HttpStatus.BAD_REQUEST,"MIXED_CREDENTIAL_REFUSED");
        }
        boolean areaWrite = switch (operation) {
            case "area-collection", "area-lifecycle", "area-editor", "area-repair" -> HttpMethod.POST.equals(method);
            case "area-record" -> HttpMethod.PUT.equals(method);
            default -> false;
        };
        boolean metadataWrite = (operation.equals("area-metadata") || operation.equals("routing-metadata") || operation.equals("routing-mutation"))
                && (HttpMethod.POST.equals(method) || HttpMethod.PUT.equals(method));
        // Match the owning handlers' decoded envelope limits for area, metadata and annotation writes. An editor
        // route operation has the same envelope as its public counterpart.
        String envelope = operation.startsWith("editor-") ? operation.substring("editor-".length()) : operation;
        long maxBody = machine ? 0 : areaWrite ? 10_000_000
                : metadataWrite ? 65_536
                : envelope.equals("spatial-relations") || envelope.startsWith("analysis-") ? 1_048_576
                : envelope.equals("routing-annotation") ? 400_000
                // The edge's strict release-manifest and catalogue-bundle decoders bound these at 32768 bytes.
                : envelope.equals("release-manifest") ? 32_768
                : envelope.equals("route-calculate") || envelope.equals("route-directions") ? 4096 : 8192;
        if(exchange.getRequest().getHeaders().getContentLength()>maxBody)return fail(exchange,HttpStatus.PAYLOAD_TOO_LARGE,"PAYLOAD_TOO_LARGE");
        if(exchange.getRequest().getHeaders().containsKey(HttpHeaders.CONTENT_ENCODING))return fail(exchange,HttpStatus.UNSUPPORTED_MEDIA_TYPE,"REQUEST_ENCODING_REFUSED");
        if(!HttpMethod.POST.equals(method)&&!areaWrite&&!metadataWrite
                &&(exchange.getRequest().getHeaders().getContentLength()>0||exchange.getRequest().getHeaders().containsKey(HttpHeaders.TRANSFER_ENCODING)))
            return fail(exchange,HttpStatus.BAD_REQUEST,"BODY_NOT_ALLOWED");
        // Session lifecycle has its own population, so a private-resource flood cannot stop sign-in or sign-out.
        // Client buckets are checked first: a request refused for its own client never spends the shared total.
        String population=policy.publicRoute()?"public":policy.operation().startsWith("session-")?"session":"private";
        int replicas=properties.getMaximumReplicas();
        int total=(policy.publicRoute()?properties.getPublicRequestsPerSecond():properties.getPrivateRequestsPerSecond())/replicas;
        int perClient=(policy.publicRoute()?properties.getPublicClientRequestsPerSecond():properties.getPrivateClientRequestsPerSecond())/replicas;
        String client=clientKey(clientAddress.apply(exchange.getRequest()));
        long now=monotonic.getAsLong();
        if(!peers.get(population+":"+client,k->new Bucket()).take(now,perClient,SECOND))return refuse(exchange,"1");
        if((policy.operation().equals("session-otp")||policy.operation().equals("session-login"))
                &&!signIns.get(client,k->new Bucket()).take(now,properties.getSignInClientRequestsPerHour()/replicas,HOUR))return refuse(exchange,"3600");
        if(!totals.computeIfAbsent(population,k->new Bucket()).take(now,total,SECOND))return refuse(exchange,"1");
        String pseudonym=policy.backend().equals("edge")?pseudonym(client):null;
        if(policy.backend().equals("edge")&&pseudonym==null)return fail(exchange,HttpStatus.SERVICE_UNAVAILABLE,"MAPS_ADMISSION_UNAVAILABLE");
        var request=exchange.getRequest().mutate().headers(headers->{
            for(String header:List.of("X-User-Id","X-User-Roles","X-User-Phone","X-Session-Id","X-Identity-Signature","X-Issued-At","X-Client-Fingerprint",
                    "Forwarded","X-Forwarded-For","X-Forwarded-Host","X-Forwarded-Proto","X-Forwarded-Port","X-Forwarded-Prefix","X-Forwarded-Client-Cert",
                    "X-Request-ID","X-B3-TraceId","X-B3-SpanId","traceparent","tracestate","Proxy-Authorization","X-E2E-Runner-Secret",CLIENT_HEADER)) headers.remove(header);
            if(pseudonym!=null)headers.set(CLIENT_HEADER,pseudonym);
            if(policy.publicRoute()) { headers.remove(HttpHeaders.AUTHORIZATION);headers.remove(HttpHeaders.COOKIE);headers.remove("X-CSRF-Token"); }
            headers.set("X-Request-ID",UUID.randomUUID().toString());
        }).build();
        // A body is bounded by progress, not by a fixed total (the edge applies the same rule): UPLOAD_IDLE without
        // bytes, or an average below UPLOAD_FLOOR after it, is 408. An upload holds an upload slot; the route's
        // processing budget starts when the body ends, so a slow valid upload is not charged to processing.
        boolean upload=requestHeaders.getContentLength()>0||requestHeaders.containsKey(HttpHeaders.TRANSFER_ENCODING);
        var uploadSlot=new AtomicBoolean();
        if(upload) {
            if(uploads.incrementAndGet()>Math.max(1,properties.getConcurrentUploads()/replicas)){uploads.decrementAndGet();return refuse(exchange,"1");}
            uploadSlot.set(true);
        }
        Runnable endUpload=()->{if(uploadSlot.compareAndSet(true,false))uploads.decrementAndGet();};
        var bodyEnded=Sinks.<Void>empty();
        if(!upload)bodyEnded.tryEmitEmpty();
        var count=new AtomicLong();
        var bounded=new ServerHttpRequestDecorator(request){
            @Override public Flux<DataBuffer> getBody(){
                long started=monotonic.getAsLong();
                return super.getBody().<DataBuffer>handle((buffer,sink)->{
                    long bytes=count.addAndGet(buffer.readableByteCount());
                    long elapsed=monotonic.getAsLong()-started;
                    if(bytes>maxBody){DataBufferUtils.release(buffer);sink.error(new BodyRefused(true));}
                    else if(elapsed>UPLOAD_IDLE.toNanos()&&bytes<(elapsed-UPLOAD_IDLE.toNanos())/(double)SECOND*UPLOAD_FLOOR)
                        {DataBufferUtils.release(buffer);sink.error(new BodyRefused(false));}
                    else sink.next(buffer);
                }).timeout(UPLOAD_IDLE,Flux.error(new BodyRefused(false)))
                  .doFinally(signal->{endUpload.run();bodyEnded.tryEmitEmpty();})
                  .doOnDiscard(DataBuffer.class,DataBufferUtils::release);
            }
        };
        var admitted=exchange.mutate().request(bounded).build();admitted.getAttributes().put(ADMITTED,true);
        // Route budgets are processing budgets (MapsGatewayConfiguration disables the gateway's own response timeout,
        // which counts from the start of the upload). The budget runs from the end of the body, or from now for a
        // bodyless request, until the response is committed. A body never read to its end is bounded by the slowest
        // valid upload of maxBody.
        long budget=route.getMetadata().get(PROCESSING_TIMEOUT) instanceof Number n?n.longValue():3000L;
        var committed=new AtomicBoolean();
        exchange.getResponse().beforeCommit(()->{committed.set(true);return Mono.empty();});
        Duration backstop=UPLOAD_IDLE.plusMillis(maxBody*1000/UPLOAD_FLOOR).plusMillis(budget);
        Mono<Void> expired=Mono.firstWithSignal(bodyEnded.asMono().then(Mono.delay(Duration.ofMillis(budget))),Mono.delay(backstop))
                .then(Mono.defer(()->committed.get()?Mono.<Void>never():Mono.error(new ProcessingTimeout())));
        if(!policy.publicRoute()) {
            exchange.getResponse().getHeaders().setCacheControl("no-store");
            // Netty appends upstream response headers after this filter runs.
            // Finalize the private contract at commit, preserving all Vary axes.
            exchange.getResponse().beforeCommit(()->{
                var headers=exchange.getResponse().getHeaders();
                headers.setCacheControl("private, no-store");
                var vary=new java.util.TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
                vary.addAll(headers.getVary());
                if(vary.contains("*"))headers.setVary(List.of("*"));
                else {vary.add("Cookie");vary.add("Authorization");headers.setVary(new java.util.ArrayList<>(vary));}
                return Mono.empty();
            });
        }
        return Mono.firstWithSignal(chain.filter(admitted),expired).doFinally(signal->endUpload.run())
                .onErrorResume(BodyRefused.class,refused->fail(exchange,
                refused.tooLarge?HttpStatus.PAYLOAD_TOO_LARGE:HttpStatus.REQUEST_TIMEOUT,
                refused.tooLarge?"PAYLOAD_TOO_LARGE":"UPLOAD_TIMEOUT"))
                .onErrorResume(ProcessingTimeout.class,timeout->fail(exchange,HttpStatus.GATEWAY_TIMEOUT,"UPSTREAM_TIMEOUT"))
                // A lost upstream (refused on every resolved address, reset, or closed before the response) is a bounded
                // dependency failure, not a gateway fault. Once the response is committed its status cannot change, so
                // the error propagates and the connection is aborted rather than completing a truncated body.
                .onErrorResume(error->!committed.get()&&upstreamLost(error),error->{
                    LOG.warn("maps upstream unavailable",kv("operation","maps_upstream"),kv("stage","exchange"),kv("route",route.getId()),
                            kv("maps_operation",operation),kv("cause",error.getClass().getSimpleName()),
                            kv("elapsed_ms",(monotonic.getAsLong()-now)/1_000_000L));
                    return fail(exchange,HttpStatus.BAD_GATEWAY,"UPSTREAM_UNAVAILABLE");
                });
    }
    private static final Logger LOG=LoggerFactory.getLogger(MapsGatewayFilter.class);
    static boolean upstreamLost(Throwable error) {
        for(Throwable t=error;t!=null;t=t.getCause())
            if(t instanceof java.io.IOException||t instanceof reactor.netty.channel.AbortedException)return true;
        return false;
    }
    private static final class ProcessingTimeout extends RuntimeException {
        ProcessingTimeout(){super(null,null,false,false);}
    }
    private static final class BodyRefused extends RuntimeException {
        final boolean tooLarge;
        BodyRefused(boolean tooLarge){super(null,null,false,false);this.tooLarge=tooLarge;}
    }
    private static Mono<Void> fail(ServerWebExchange exchange,HttpStatus status,String code) {
        exchange.getResponse().setStatusCode(status);exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().setCacheControl("no-store");
        byte[] bytes=("{\"code\":\""+code+"\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }
}
