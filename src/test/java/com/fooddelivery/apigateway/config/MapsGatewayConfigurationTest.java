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
        var properties=new MapsGatewayProperties();properties.setEnabled(true);properties.setPublicOrigin("https://maps.test");
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
    @Test void plainHttpIsOnlyForPublicRouteBackendsOnThePrivateNetwork(){
        for(java.util.function.BiConsumer<MapsGatewayProperties,String> backend:List.<java.util.function.BiConsumer<MapsGatewayProperties,String>>of(
                MapsGatewayProperties::setPublicUri,MapsGatewayProperties::setAssetsUri,MapsGatewayProperties::setPostalUri,MapsGatewayProperties::setRoutingUri)){
            var allowed=properties();backend.accept(allowed,"http://private-service:8781");allowed.validate();
            for(String refused:List.of("http://10.0.0.5:8781","http://maps.example.com","http://[::1]:8781","http://2130706433","ftp://service","http://service/path","http://user@service")){
                var candidate=properties();backend.accept(candidate,refused);
                assertThrows(IllegalStateException.class,candidate::validate,refused);
            }
        }
        var edge=properties();edge.setEdgeUri("http://edge:8780");
        assertThrows(IllegalStateException.class,edge::validate,"the session route must stay on TLS");
    }
    @Test void everyRouteOnABackendThatMayBePlainStripsCredentials(){
        String hash="a".repeat(64);
        for(String path:List.of("/public/"+hash+"/basemap.json","/assets/"+hash+"/styles/streets.json","/assets/"+hash+"/glyphs/0-255.pbf",
                "/api/v1/countries/IN/postal-codes/560001","/api/v1/postal-codes/at-point","/api/v1/routes/calculate","/api/v1/routes/capabilities","/api/v1/routes/directions")){
            var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(path);
            assertNotNull(policy,path);assertTrue(policy.publicRoute(),path);
            assertTrue(List.of("public","assets","postal","routing").contains(policy.backend()),path);
        }
        for(String path:List.of("/api/v1/maps-session/session","/api/v1/maps-session/login","/api/v1/resources")){
            var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(path);
            assertEquals("edge",policy.backend(),path);assertFalse(policy.publicRoute(),path);
        }
    }
    @Test void foodDeliveryKeepsItsFrontendLogController() {
        try (var context = new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.getEnvironment().setActiveProfiles("food-delivery");
            context.register(com.fooddelivery.apigateway.controller.FrontendLogController.class);
            context.refresh();
            assertEquals(1, context.getBeansOfType(com.fooddelivery.apigateway.controller.FrontendLogController.class).size());
        }
    }
    @Test void directionsPanelPathsUseOnlyTheirDeclaredRoutingMethods() {
        for (String base : List.of("", "/maps-service")) {
            for (var entry : java.util.Map.of("capabilities", org.springframework.http.HttpMethod.GET,
                    "directions", org.springframework.http.HttpMethod.POST).entrySet()) {
                var policy = com.fooddelivery.apigateway.security.MapsRoutes.classify(base + "/api/v1/routes/" + entry.getKey());
                assertNotNull(policy);
                assertEquals("routing", policy.backend());
                assertTrue(policy.publicRoute());
                assertEquals(java.util.Set.of(entry.getValue()), policy.methods());
            }
        }
        assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify("/api/v1/routes/directions/private"));
    }
    @Test void thePublicOriginIsRequiredAndMustBeOneHttpsOrigin(){
        for(String refused:java.util.Arrays.asList(null,"${MAPS_PUBLIC_ORIGIN}","http://maps.test","https://maps.test/","https://maps.test/maps","*")){
            var candidate=properties();candidate.setPublicOrigin(refused);
            assertThrows(IllegalStateException.class,candidate::validate,String.valueOf(refused));
        }
        var port=properties();port.setPublicOrigin("https://localhost:8443");port.validate();
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
