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
        // Match the owning handlers' decoded envelope limits for area, metadata and annotation writes.
        long maxBody = machine ? 0 : areaWrite ? 10_000_000
                : metadataWrite ? 65_536
                : operation.equals("spatial-relations") || operation.startsWith("analysis-") ? 1_048_576
                : operation.equals("routing-annotation") ? 400_000
                : operation.equals("route-calculate") || operation.equals("route-directions") ? 4096 : 8192;
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
        var request=exchange.getRequest().mutate().headers(headers->{
            for(String header:List.of("X-User-Id","X-User-Roles","X-User-Phone","X-Session-Id","X-Identity-Signature","X-Issued-At","X-Client-Fingerprint",
                    "Forwarded","X-Forwarded-For","X-Forwarded-Host","X-Forwarded-Proto","X-Forwarded-Port","X-Forwarded-Prefix","X-Forwarded-Client-Cert",
                    "X-Request-ID","X-B3-TraceId","X-B3-SpanId","traceparent","tracestate","Proxy-Authorization","X-E2E-Runner-Secret")) headers.remove(header);
            if(policy.publicRoute()) { headers.remove(HttpHeaders.AUTHORIZATION);headers.remove(HttpHeaders.COOKIE);headers.remove("X-CSRF-Token"); }
            headers.set("X-Request-ID",UUID.randomUUID().toString());
        }).build();
        var count=new AtomicLong();
        var bounded=new ServerHttpRequestDecorator(request){
            @Override public Flux<DataBuffer> getBody(){
                return super.getBody().<DataBuffer>handle((buffer,sink)->{
                    if(count.addAndGet(buffer.readableByteCount())>maxBody){DataBufferUtils.release(buffer);sink.error(new BodyRefused(true));}
                    else sink.next(buffer);
                }).takeUntilOther(Mono.delay(Duration.ofSeconds(2)).then(Mono.error(new BodyRefused(false))))
                  .doOnDiscard(DataBuffer.class,DataBufferUtils::release);
            }
        };
        var admitted=exchange.mutate().request(bounded).build();admitted.getAttributes().put(ADMITTED,true);
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
        return chain.filter(admitted).onErrorResume(BodyRefused.class,refused->fail(exchange,
                refused.tooLarge?HttpStatus.PAYLOAD_TOO_LARGE:HttpStatus.REQUEST_TIMEOUT,
                refused.tooLarge?"PAYLOAD_TOO_LARGE":"UPLOAD_TIMEOUT"));
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
