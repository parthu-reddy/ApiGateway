package com.fooddelivery.apigateway.filter;

import com.fooddelivery.apigateway.config.MapsGatewayProperties;
import com.fooddelivery.apigateway.security.MapsRoutes;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
    private static final class Bucket {
        long start; int used; boolean initialized;
        synchronized boolean take(long now, int limit) {
            if (!initialized||now-start>=1_000_000_000L) {start=now;used=0;initialized=true;}
            if(used>=limit)return false;used++;return true;
        }
    }
    public MapsGatewayFilter(MapsGatewayProperties properties) { this(properties,System::nanoTime); }
    public MapsGatewayFilter(MapsGatewayProperties properties, LongSupplier monotonic) { this.properties=properties;this.monotonic=monotonic; }
    public static boolean admitted(ServerWebExchange exchange) { return Boolean.TRUE.equals(exchange.getAttribute(ADMITTED)); }
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
        if(!policy.publicRoute()&&exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION))
            return fail(exchange,HttpStatus.BAD_REQUEST,"MIXED_CREDENTIAL_REFUSED");
        long maxBody=policy.operation().equals("route-calculate")?4096:8192;
        if(exchange.getRequest().getHeaders().getContentLength()>maxBody)return fail(exchange,HttpStatus.PAYLOAD_TOO_LARGE,"PAYLOAD_TOO_LARGE");
        if(exchange.getRequest().getHeaders().containsKey(HttpHeaders.CONTENT_ENCODING))return fail(exchange,HttpStatus.UNSUPPORTED_MEDIA_TYPE,"REQUEST_ENCODING_REFUSED");
        if(exchange.getRequest().getMethod()!=org.springframework.http.HttpMethod.POST
                &&(exchange.getRequest().getHeaders().getContentLength()>0||exchange.getRequest().getHeaders().containsKey(HttpHeaders.TRANSFER_ENCODING)))
            return fail(exchange,HttpStatus.BAD_REQUEST,"BODY_NOT_ALLOWED");
        String population=policy.publicRoute()?"public":"private";
        int limit=(policy.publicRoute()?properties.getPublicRequestsPerSecond():properties.getPrivateRequestsPerSecond())/properties.getMaximumReplicas();
        String address=exchange.getRequest().getRemoteAddress()==null?"unknown":exchange.getRequest().getRemoteAddress().getHostString();
        long now=monotonic.getAsLong();
        if(!totals.computeIfAbsent(population,k->new Bucket()).take(now,limit)||!peers.get(population+":"+address,k->new Bucket()).take(now,limit)) {
            exchange.getResponse().getHeaders().set("Retry-After","1");return fail(exchange,HttpStatus.TOO_MANY_REQUESTS,"ADMISSION_EXCEEDED");
        }
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
        if(!policy.publicRoute())exchange.getResponse().getHeaders().setCacheControl("no-store");
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
