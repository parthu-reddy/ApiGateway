package com.fooddelivery.apigateway.filter;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import static org.junit.jupiter.api.Assertions.*;

class MapsCorsFilterTest {
    static final String ORIGIN="https://maps.example";
    static final String TILE="/public/"+"a".repeat(64)+"/tiles/0/0/0.mvt";

    MockServerWebExchange run(MockServerHttpRequest request, java.util.function.Consumer<HttpHeaders> downstream){
        var exchange=MockServerWebExchange.from(request);
        new MapsCorsFilter().filter(exchange,e->{downstream.accept(e.getResponse().getHeaders());return e.getResponse().setComplete();}).block();
        return exchange;
    }

    @Test void publicResponseKeepsOneGatewayOriginInsteadOfAppendingTheBackendWildcard(){
        for(var shape:List.of(List.of(ORIGIN,"*"),List.of(ORIGIN+", *"),List.of("*",ORIGIN))){
            var e=run(MockServerHttpRequest.get(TILE).header(HttpHeaders.ORIGIN,ORIGIN).build(),
                    h->shape.forEach(v->h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,v)));
            assertEquals(List.of(ORIGIN),e.getResponse().getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN),shape.toString());
        }
        // Without a Gateway grant (no CORS request) the backend's single public value is left alone.
        var plain=run(MockServerHttpRequest.get(TILE).build(),h->h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,"*"));
        assertEquals(List.of("*"),plain.getResponse().getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        var credentialed=run(MockServerHttpRequest.get(TILE).header(HttpHeaders.ORIGIN,ORIGIN).build(),
                h->{h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,ORIGIN);h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,"true");});
        assertNull(credentialed.getResponse().getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
    }

    @Test void publicPreflightGrantsOnlyTheRoutesOwnMethods(){
        var asset=run(MockServerHttpRequest.options(TILE).header(HttpHeaders.ORIGIN,ORIGIN).header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD,"GET").build(),
                h->{h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,ORIGIN);h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,"GET,HEAD,POST,PUT");});
        assertEquals("GET,HEAD",asset.getResponse().getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS));
        var directions=run(MockServerHttpRequest.options("/api/v1/routes/directions").header(HttpHeaders.ORIGIN,ORIGIN).header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD,"POST").build(),
                h->{h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,ORIGIN);h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,"GET,HEAD,POST");});
        assertEquals("POST",directions.getResponse().getHeaders().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS));
    }

    @Test void privateRouteNeverCarriesCorsGrants(){
        var e=run(MockServerHttpRequest.get("/api/v1/maps-session/session").header(HttpHeaders.ORIGIN,ORIGIN).build(),
                h->{h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,ORIGIN);h.add(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,"true");});
        assertNull(e.getResponse().getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        assertNull(e.getResponse().getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
    }
}
