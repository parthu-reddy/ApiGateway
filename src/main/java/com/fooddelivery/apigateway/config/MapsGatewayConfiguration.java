package com.fooddelivery.apigateway.config;

import com.fooddelivery.apigateway.filter.MapsGatewayFilter;
import com.fooddelivery.apigateway.filter.MapsCorsFilter;
import com.fooddelivery.apigateway.security.MapsRoutes;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.config.HttpClientProperties;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods=false)
@EnableConfigurationProperties(MapsGatewayProperties.class)
public class MapsGatewayConfiguration {
    @Bean MapsCorsFilter mapsCorsFilter(){return new MapsCorsFilter();}
    @Bean MapsGatewayFilter mapsGatewayFilter(MapsGatewayProperties properties, RateLimiterConfig limiter) { return new MapsGatewayFilter(properties,limiter::clientAddress); }
    @Bean
    @ConditionalOnProperty(name="gateway.maps.enabled",havingValue="true")
    RouteLocator mapsRoutes(MapsGatewayProperties properties, RouteLocatorBuilder builder, HttpClientProperties client) {
        properties.validate();
        var ssl=client.getSsl();
        if(ssl.isUseInsecureTrustManager()||ssl.getKeyStore()==null||ssl.getKeyStore().isBlank()||ssl.getTrustedX509Certificates().isEmpty())
            throw new IllegalStateException("Maps upstream requires scoped TLS client keys and explicit trust roots");
        var routes=builder.routes();
        var backends=Map.of("edge",properties.getEdgeUri(),"public",properties.getPublicUri(),"assets",properties.getAssetsUri(),"postal",properties.getPostalUri(),"routing",properties.getRoutingUri());
        // Each bounded analysis keeps its domain deadline. These routes use the
        // same private routing service, without retries or global timeout changes.
        // response-timeout -1 turns off the gateway's own timeout, which counts from the start of the upload;
        // MapsGatewayFilter applies PROCESSING_TIMEOUT from the end of the request body instead.
        for(var operation:Map.of("matrix",22000L,"optimise",22000L,"isochrones",12000L,"match",10000L,"elevation",3000L,"capabilities",5000L).entrySet()) {
            routes.route("maps-v1-analysis-"+operation.getKey(),predicate->predicate.order(-100).predicate(exchange->{
                var policy=MapsRoutes.classify(exchange.getRequest().getURI().getPath());
                return policy!=null&&policy.operation().equals("analysis-"+operation.getKey());
            }).filters(filters->filters.rewritePath("/maps-service/(?<segment>.*)","/${segment}"))
              .metadata("maps.contract","v1").metadata("maps.backend","routing")
              .metadata("connect-timeout",300).metadata("response-timeout",-1L)
              .metadata(MapsGatewayFilter.PROCESSING_TIMEOUT,operation.getValue()).uri(properties.getRoutingUri()));
        }
        for(var backend:backends.entrySet()) {
            routes.route("maps-v1-"+backend.getKey(), predicate->predicate.order(-100).predicate(exchange->{
                var policy=MapsRoutes.classify(exchange.getRequest().getURI().getPath());
                return policy!=null&&policy.backend().equals(backend.getKey())&&!policy.operation().startsWith("analysis-");
            }).filters(filters->{
                // Only edge API paths are rewritten; immutable public style/tile URLs retain
                // their configured hosting base, release identity and range/conditional bytes.
                if(backend.getKey().equals("edge")||backend.getKey().equals("postal")||backend.getKey().equals("routing"))
                    filters.rewritePath("/maps-service/(?<segment>.*)","/${segment}");
                return filters;
            }).metadata("maps.contract","v1").metadata("maps.backend",backend.getKey())
              .metadata("connect-timeout",300).metadata("response-timeout",-1L)
              .metadata(MapsGatewayFilter.PROCESSING_TIMEOUT,3000L).uri(backend.getValue()));
        }
        return routes.build();
    }
}
