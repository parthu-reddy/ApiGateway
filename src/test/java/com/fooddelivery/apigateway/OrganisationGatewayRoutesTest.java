package com.fooddelivery.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.context.properties.bind.*;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Tests the owner-deployed config, because ConfigService overrides the packaged fallback. */
class OrganisationGatewayRoutesTest {
    @Test void deploymentRoutesPublicOrganisationPathsAndNeverAddsInternalMembershipToRbac() throws Exception {
        var env=new StandardEnvironment();
        var resource=new FileSystemResource("../Deployment/api-gateway.yml");
        assertTrue(resource.exists(),"Run from the assembled workspace’s ApiGateway checkout");
        for(var source:new YamlPropertySourceLoader().load("deployment",resource)){env.getPropertySources().addFirst(source);}
        var authenticated=Binder.get(env).bind("rbac.rules.authenticated",Bindable.listOf(String.class)).orElseThrow(IllegalStateException::new);
        assertTrue(authenticated.contains("/api/v1/organisations"));assertTrue(authenticated.contains("/api/v1/organisation-invitations"));
        boolean found=false;
        for(int i=0;env.getProperty("spring.cloud.gateway.routes["+i+"].id")!=null;i++){
            if(!"identity-service".equals(env.getProperty("spring.cloud.gateway.routes["+i+"].id"))){continue;}
            assertEquals("lb://identity-service",env.getProperty("spring.cloud.gateway.routes["+i+"].uri"));
            String paths=env.getProperty("spring.cloud.gateway.routes["+i+"].predicates[0]");
            for(String path:List.of("/api/v1/organisations/**","/api/v1/organisation-invitations/**","/api/v1/internal/organisations/**","/api/v1/internal/admin/organisations/**","/api/v1/internal/admin/audit-events/**")){assertTrue(paths.contains(path),path);}
            found=true;
        }
        assertTrue(found,"Identity route must exist");
        boolean restaurantRoute=false;
        for(int i=0;env.getProperty("spring.cloud.gateway.routes["+i+"].id")!=null;i++){
            if(!"restaurant-service".equals(env.getProperty("spring.cloud.gateway.routes["+i+"].id"))){continue;}
            String paths=env.getProperty("spring.cloud.gateway.routes["+i+"].predicates[0]");
            assertTrue(paths.contains("/api/v1/internal/restaurants/**"), "Internal paths must reach the rejecting security filter");
            restaurantRoute=true;
        }
        assertTrue(restaurantRoute,"Restaurant route must exist");
        for(String role:List.of("authenticated","customer","restaurant","delivery","admin")){
            var rules=Binder.get(env).bind("rbac.rules."+role,Bindable.listOf(String.class)).orElse(List.of());
            for(String rule:rules){assertFalse("/api/v1/internal/organisations/x/members".startsWith(rule),role+": "+rule);assertFalse("/api/v1/internal/users/x/organisations".startsWith(rule),role+": "+rule);
                assertFalse("/api/v1/internal/restaurants/users/x/outlets".startsWith(rule),role+": "+rule);
                assertFalse("/api/v1/internal/restaurants/outlets/x/organisation".startsWith(rule),role+": "+rule);}
        }
    }

    @Test void deployedCorsAllowsOrganisationPatchAndKeepsOriginRestrictions() throws Exception {
        var env=new StandardEnvironment();
        var resource=new FileSystemResource("../Deployment/api-gateway.yml");
        assertTrue(resource.exists(), "Assembled deployment config is required");
        for(var source:new YamlPropertySourceLoader().load("deployment",resource)){env.getPropertySources().addFirst(source);}
        env.getPropertySources().addFirst(new org.springframework.core.env.MapPropertySource("origins",Map.of("ALLOWED_ORIGINS","https://ui.test")));
        var properties=Binder.get(env).bind("spring.cloud.gateway.globalcors",
                Bindable.of(org.springframework.cloud.gateway.config.GlobalCorsProperties.class)).orElseThrow(IllegalStateException::new);
        var cors=properties.getCorsConfigurations().get("/**");assertNotNull(cors);
        for(boolean preflight:List.of(false,true)) {
            var request=preflight
                ? org.springframework.mock.http.server.reactive.MockServerHttpRequest.options("https://gateway.test/api/v1/organisations/x/members/y")
                    .header("Access-Control-Request-Method","PATCH")
                : org.springframework.mock.http.server.reactive.MockServerHttpRequest.patch("https://gateway.test/api/v1/organisations/x/members/y");
            var exchange=org.springframework.mock.web.server.MockServerWebExchange.from(request.header("Origin","https://ui.test"));
            assertTrue(new org.springframework.web.cors.reactive.DefaultCorsProcessor().process(cors,exchange),
                    "The deployed CORS policy must admit member role PATCH (preflight="+preflight+")");
        }
        var outsider=org.springframework.mock.web.server.MockServerWebExchange.from(
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.patch("https://gateway.test/api/v1/organisations/x")
                    .header("Origin","https://untrusted.test"));
        assertFalse(new org.springframework.web.cors.reactive.DefaultCorsProcessor().process(cors,outsider));
        assertEquals(org.springframework.http.HttpStatus.FORBIDDEN,outsider.getResponse().getStatusCode());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={"../Deployment/api-gateway.yml","src/main/resources/application.yml"})
    void partnerRoutesBindToTheCorrectServiceWithRateLimitersAndOnlyOwnPathsAreAuthenticated(String file) throws Exception {
        var env=new StandardEnvironment();var resource=new FileSystemResource(file);assertTrue(resource.exists());
        for(var source:new YamlPropertySourceLoader().load("partner-routes",resource)) env.getPropertySources().addFirst(source);
        var expected=Map.of("/api/v1/restaurant-onboarding/organisations/x/application","restaurant-service",
                "/api/v1/delivery-onboarding/application","delivery-service",
                "/api/v1/verification/status/me","government-id-validation-service",
                "/api/v1/internal/admin/restaurant-applications/x/approve","restaurant-service",
                "/api/v1/internal/admin/delivery-applications/x/approve","delivery-service",
                "/api/v1/internal/admin/verification/documents/x/download-url","government-id-validation-service");
        for(var entry:expected.entrySet()) {
            boolean matched=false;
            for(int i=0;env.getProperty("spring.cloud.gateway.routes["+i+"].id")!=null;i++) {
                String value=env.getProperty("spring.cloud.gateway.routes["+i+"].predicates[0]");
                if(value==null || !value.startsWith("Path=")) continue;
                var config=new org.springframework.cloud.gateway.handler.predicate.PathRoutePredicateFactory.Config();
                config.setPatterns(Arrays.stream(value.substring(5).split(",")).map(String::trim).toList());
                var predicate=new org.springframework.cloud.gateway.handler.predicate.PathRoutePredicateFactory().apply(config);
                if(!predicate.test(org.springframework.mock.web.server.MockServerWebExchange.from(
                        org.springframework.mock.http.server.reactive.MockServerHttpRequest.get(entry.getKey())))) continue;
                assertEquals("lb://"+entry.getValue(),env.getProperty("spring.cloud.gateway.routes["+i+"].uri"),entry.getKey());
                boolean limited=false;
                for(int j=0;env.getProperty("spring.cloud.gateway.routes["+i+"].filters["+j+"].name")!=null;j++)
                    limited |= "RequestRateLimiter".equals(env.getProperty("spring.cloud.gateway.routes["+i+"].filters["+j+"].name"));
                assertTrue(limited,"Rate limiter missing for "+entry.getKey());matched=true;break;
            }
            assertTrue(matched,"No route for "+entry.getKey()+" in "+file);
        }
        var rules=Binder.get(env).bind("rbac",Bindable.of(com.fooddelivery.apigateway.config.RbacConfig.class)).orElseThrow(IllegalStateException::new);
        for(String path:List.of("/api/v1/restaurant-onboarding","/api/v1/delivery-onboarding","/api/v1/verification"))
            assertTrue(rules.getRules().get("authenticated").contains(path),file+" "+path);
        for(var paths:rules.getRules().values()) for(String prefix:paths)
            for(String internal:List.of("/api/v1/internal/delivery-applications/x/context","/api/v1/internal/brands/x/verification-request"))
                assertFalse(internal.equals(prefix) || internal.startsWith(prefix+"/"),file+" exposes "+internal);
    }
}
