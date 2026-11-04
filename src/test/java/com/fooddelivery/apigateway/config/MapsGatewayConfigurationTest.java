package com.fooddelivery.apigateway.config;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.config.HttpClientProperties;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.filter.factory.RewritePathGatewayFilterFactory;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;

class MapsGatewayConfigurationTest {
    MapsGatewayProperties properties(){
        var properties=new MapsGatewayProperties();properties.setEnabled(true);
        properties.setEdgeUri("https://edge.test");properties.setPublicUri("https://public.test");
        properties.setAssetsUri("https://assets.test");properties.setPostalUri("https://postal.test");properties.setRoutingUri("https://routing.test");
        return properties;
    }
    @Test void sourceRoutesPrecedeLegacySubpathAndDoNotInheritSharedRetryFilters(){
        try(var context=new GenericApplicationContext()){
            context.registerBean(RewritePathGatewayFilterFactory.class,RewritePathGatewayFilterFactory::new);
            var defaults=new GatewayProperties();defaults.setDefaultFilters(List.of(new FilterDefinition("Retry=3")));
            context.registerBean(GatewayProperties.class,()->defaults);context.refresh();
            var client=new HttpClientProperties();client.getSsl().setKeyStore("file:/owned-fixture-only.p12");client.getSsl().setTrustedX509Certificates(List.of("file:/owned-fixture-only-ca.pem"));
            var locator=new MapsGatewayConfiguration().mapsRoutes(properties(),new RouteLocatorBuilder(context),client);
            var routes=locator.getRoutes().collectList().block(Duration.ofSeconds(2));assertNotNull(routes);assertEquals(5,routes.size());
            for(Route route:routes){
                assertEquals(-100,route.getOrder());assertEquals("v1",route.getMetadata().get("maps.contract"));
                boolean rewrite=List.of("edge","postal","routing").contains(route.getMetadata().get("maps.backend"));
                assertEquals(rewrite?1:0,route.getFilters().size(),"programmatic Maps routes must not acquire default Retry/Redis filters");
            }
            for(String base:List.of("","/maps-service")){
                var exchange=MockServerWebExchange.from(MockServerHttpRequest.get(base+"/api/v1/maps-session/session"));
                var selected=routes.stream().filter(route->Boolean.TRUE.equals(Mono.from(route.getPredicate().apply(exchange)).block(Duration.ofSeconds(1)))).toList();
                assertEquals(1,selected.size());assertEquals("maps-v1-edge",selected.getFirst().getId());
                selected.getFirst().getFilters().getFirst().filter(exchange,rewritten->{assertEquals("/api/v1/maps-session/session",rewritten.getRequest().getURI().getPath());return Mono.empty();}).block(Duration.ofSeconds(1));
            }
        }
    }
    @Test void mapsUpstreamCannotUseInsecureOrUnconfiguredClientTLS(){
        try(var context=new GenericApplicationContext()){
            context.refresh();var configuration=new MapsGatewayConfiguration();var client=new HttpClientProperties();
            assertThrows(IllegalStateException.class,()->configuration.mapsRoutes(properties(),new RouteLocatorBuilder(context),client));
            client.getSsl().setKeyStore("file:/owned-fixture.p12");client.getSsl().setTrustedX509Certificates(List.of("file:/owned-ca.pem"));client.getSsl().setUseInsecureTrustManager(true);
            assertThrows(IllegalStateException.class,()->configuration.mapsRoutes(properties(),new RouteLocatorBuilder(context),client));
        }
    }
}
