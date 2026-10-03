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
        org.junit.jupiter.api.Assumptions.assumeTrue(resource.exists(),"Run from the assembled workspace’s ApiGateway checkout");
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
        for(String role:List.of("authenticated","customer","restaurant","delivery","admin")){
            var rules=Binder.get(env).bind("rbac.rules."+role,Bindable.listOf(String.class)).orElse(List.of());
            for(String rule:rules){assertFalse("/api/v1/internal/organisations/x/members".startsWith(rule),role+": "+rule);assertFalse("/api/v1/internal/users/x/organisations".startsWith(rule),role+": "+rule);}
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
}
