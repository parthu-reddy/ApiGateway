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
        properties.setAssetsUri("https://assets.test");properties.setPostalUri("https://postal.test");properties.setClientKeySecret("ab".repeat(32));
        return properties;
    }
    @Test void sourceRoutesPrecedeLegacySubpathAndDoNotInheritSharedRetryFilters(){
        try(var context=new GenericApplicationContext()){
            context.registerBean(RewritePathGatewayFilterFactory.class,RewritePathGatewayFilterFactory::new);
            var defaults=new GatewayProperties();defaults.setDefaultFilters(List.of(new FilterDefinition("Retry=3")));
            context.registerBean(GatewayProperties.class,()->defaults);context.refresh();
            var client=new HttpClientProperties();client.getSsl().setKeyStore("file:/owned-fixture-only.p12");client.getSsl().setTrustedX509Certificates(List.of("file:/owned-fixture-only-ca.pem"));
            var locator=new MapsGatewayConfiguration().mapsRoutes(properties(),new RouteLocatorBuilder(context),client);
            var routes=locator.getRoutes().collectList().block(Duration.ofSeconds(2));assertNotNull(routes);assertEquals(10,routes.size());
            for(Route route:routes){
                // The gateway's own response timeout counts from the start of the upload, so every Maps route turns it
                // off and carries a processing budget that MapsGatewayFilter starts at the end of the body.
                assertEquals(-1L,route.getMetadata().get("response-timeout"),route.getId());
                assertTrue(route.getMetadata().get(com.fooddelivery.apigateway.filter.MapsGatewayFilter.PROCESSING_TIMEOUT) instanceof Long,route.getId());
                assertEquals(-100,route.getOrder());assertEquals("v1",route.getMetadata().get("maps.contract"));
                boolean rewrite=List.of("edge","postal").contains(route.getMetadata().get("maps.backend"));
                assertEquals(rewrite?1:0,route.getFilters().size(),"programmatic Maps routes must not acquire default Retry/Redis filters");
            }
            for (String base:List.of("","/maps-service")) for (String family:List.of("/api/v1/routes/","/api/v1/editor-routes/"))
                for (var entry:java.util.Map.of("matrix",22000L,"optimise",22000L,"isochrones",12000L,"match",10000L,"elevation",3000L,"analyses/capabilities",5000L).entrySet()) {
                boolean editor=family.contains("editor");
                if(editor&&entry.getKey().equals("analyses/capabilities")){assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(base+family+entry.getKey()));continue;}
                var exchange=MockServerWebExchange.from(MockServerHttpRequest.post(base+family+entry.getKey()));
                var selected=routes.stream().filter(route->Boolean.TRUE.equals(Mono.from(route.getPredicate().apply(exchange)).block(Duration.ofSeconds(1)))).toList();
                assertEquals(1,selected.size(),"Exact bounded analysis route missing or ambiguous");
                assertEquals(entry.getValue(),selected.getFirst().getMetadata().get(com.fooddelivery.apigateway.filter.MapsGatewayFilter.PROCESSING_TIMEOUT),"Analysis deadline truncated by gateway");
                // Every route operation is admitted by the edge's shared budget; it reaches routing only through the edge.
                assertEquals("edge",selected.getFirst().getMetadata().get("maps.backend"));assertEquals("edge.test",selected.getFirst().getUri().getHost());
                var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(base+family+entry.getKey());
                assertEquals(!editor,policy.publicRoute());assertEquals("edge",policy.backend());
                assertEquals(java.util.Set.of(entry.getKey().equals("analyses/capabilities")?org.springframework.http.HttpMethod.GET:org.springframework.http.HttpMethod.POST),policy.methods());
                assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(base+family+entry.getKey()+"/extra"));
            }
            for(String base:List.of("","/maps-service")) for(String path:List.of("/api/v1/routes/calculate","/api/v1/routes/directions","/api/v1/routes/capabilities","/api/v1/editor-routes/calculate","/api/v1/editor-routes/directions")){
                var exchange=MockServerWebExchange.from(MockServerHttpRequest.post(base+path));
                var selected=routes.stream().filter(route->Boolean.TRUE.equals(Mono.from(route.getPredicate().apply(exchange)).block(Duration.ofSeconds(1)))).toList();
                assertEquals(1,selected.size(),path);assertEquals("maps-v1-edge",selected.getFirst().getId(),path);
            }
            assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify("/api/v1/editor-routes/capabilities"));
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
                MapsGatewayProperties::setPublicUri,MapsGatewayProperties::setAssetsUri,MapsGatewayProperties::setPostalUri)){
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
        for(String path:List.of("/public/"+hash+"/basemap.json","/assets/"+hash+"/release.json","/maps-service/assets/"+hash+"/release.json",
                "/assets/"+hash+"/styles/streets.json","/assets/"+hash+"/glyphs/0-255.pbf",
                "/api/v1/countries/IN/postal-codes/560001","/api/v1/postal-codes/at-point")){
            var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(path);
            assertNotNull(policy,path);assertTrue(policy.publicRoute(),path);
            assertTrue(List.of("public","assets","postal").contains(policy.backend()),path);
        }
        // Public route operations are still credential-free, but they travel on the edge's mutual-TLS hop.
        for(String path:List.of("/api/v1/routes/calculate","/api/v1/routes/capabilities","/api/v1/routes/directions","/api/v1/routes/matrix")){
            var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(path);
            assertEquals("edge",policy.backend(),path);assertTrue(policy.publicRoute(),path);
        }
        for(String path:List.of("/api/v1/maps-session/session","/api/v1/maps-session/login","/api/v1/resources")){
            var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(path);
            assertEquals("edge",policy.backend(),path);assertFalse(policy.publicRoute(),path);
        }
    }
    @Test void foodDeliveryKeepsItsNonGatewayControllers() {
        try (var context = new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
            context.getEnvironment().setActiveProfiles("food-delivery");
            context.register(com.fooddelivery.apigateway.controller.FrontendLogController.class, com.fooddelivery.apigateway.controller.IndexController.class);
            context.refresh();
            assertEquals(1, context.getBeansOfType(com.fooddelivery.apigateway.controller.FrontendLogController.class).size());
            assertEquals(1, context.getBeansOfType(com.fooddelivery.apigateway.controller.IndexController.class).size());
        }
    }
    @Test void directionsPanelPathsUseOnlyTheirDeclaredRoutingMethods() {
        for (String base : List.of("", "/maps-service")) {
            for (var entry : java.util.Map.of("capabilities", org.springframework.http.HttpMethod.GET,
                    "directions", org.springframework.http.HttpMethod.POST).entrySet()) {
                var policy = com.fooddelivery.apigateway.security.MapsRoutes.classify(base + "/api/v1/routes/" + entry.getKey());
                assertNotNull(policy);
                assertEquals("edge", policy.backend());
                assertTrue(policy.publicRoute());
                assertEquals(java.util.Set.of(entry.getValue()), policy.methods());
            }
        }
        assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify("/api/v1/routes/directions/private"));
    }
    @Test void theClientKeySecretIsRequiredHexOfThirtyTwoToSixtyFourBytes(){
        for(String refused:java.util.Arrays.asList(null,"","${MAPS_GATEWAY_CLIENT_KEY_SECRET}","ab".repeat(31),"ab".repeat(65),"AB".repeat(32),"ab".repeat(32)+"a")){
            var candidate=properties();candidate.setClientKeySecret(refused);
            assertThrows(IllegalStateException.class,candidate::validate,String.valueOf(refused));
        }
        for(int bytes:new int[]{32,64}){var accepted=properties();accepted.setClientKeySecret("cd".repeat(bytes));accepted.validate();}
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
    @Test void savedAreasAdmitOnlyImplementedPrivateMethods() {
        var get = org.springframework.http.HttpMethod.GET;
        var post = org.springframework.http.HttpMethod.POST;
        var put = org.springframework.http.HttpMethod.PUT;
        String collection = "/api/v1/areas", item = collection + "/11111111-1111-4111-8111-111111111111";
        for (String alias : List.of("", "/maps-service")) {
            var declared = new java.util.LinkedHashMap<>(java.util.Map.of(collection, java.util.Set.of(get, post), item, java.util.Set.of(get, put),
                    item + "/history", java.util.Set.of(get), item + "/export", java.util.Set.of(get),
                    item + "/archive", java.util.Set.of(post), item + "/restore", java.util.Set.of(post),
                    collection + "/repair", java.util.Set.of(post), item + "/repair", java.util.Set.of(post),
                    collection + "/at-point", java.util.Set.of(get)));
            declared.put(collection + "/overlay/12/2930/1899",java.util.Set.of(get));
            for (String editor : List.of("import", "validate", "repair")) declared.put("/api/v1/area-editor/" + editor, java.util.Set.of(post));
            for (var entry : declared.entrySet()) {
                var policy = com.fooddelivery.apigateway.security.MapsRoutes.classify(alias + entry.getKey());
                assertNotNull(policy, entry.getKey());
                assertEquals("edge", policy.backend());assertFalse(policy.publicRoute());assertEquals(entry.getValue(), policy.methods());
            }
            for (String path : List.of(item + "/publication", item + "/repair/extra", collection + "/at-point/extra", collection + "/bad/history", "/api/v1/area-editor/validate/extra")) {
                assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(alias + path), path);
            }
        }
    }

    @Test void areaMetadataAndInspectionAdmitOnlyTheirPrivateOperations() {
        var get = org.springframework.http.HttpMethod.GET;
        var post = org.springframework.http.HttpMethod.POST;
        var put = org.springframework.http.HttpMethod.PUT;
        String id = "11111111-1111-4111-8111-111111111111";
        String metadata = "/api/v1/metadata/", inspect = "/api/v1/inspection/";
        for (String alias : List.of("", "/maps-service")) {
            for (var entry : java.util.Map.ofEntries(
                    java.util.Map.entry(metadata + "areas/" + id, java.util.Set.of(get)),
                    java.util.Map.entry(metadata + "records", java.util.Set.of(post)),
                    java.util.Map.entry(metadata + "records/" + id, java.util.Set.of(get, put)),
                    java.util.Map.entry(metadata + "records/" + id + "/history", java.util.Set.of(get)),
                    java.util.Map.entry(metadata + "records/" + id + "/1", java.util.Set.of(get)),
                    java.util.Map.entry(metadata + "templates", java.util.Set.of(get, post)),
                    java.util.Map.entry(metadata + "templates/" + id, java.util.Set.of(put)),
                    java.util.Map.entry(metadata + "templates/" + id + "/1", java.util.Set.of(get)),
                    java.util.Map.entry(metadata + "templates/" + id + "/retire", java.util.Set.of(post)),
                    java.util.Map.entry(metadata + "records/" + id + "/publish", java.util.Set.of(post)),
                    java.util.Map.entry(metadata + "records/" + id + "/withdraw", java.util.Set.of(post)),
                    java.util.Map.entry(inspect + "areas/" + id + "/1", java.util.Set.of(get))).entrySet()) {
                var policy = com.fooddelivery.apigateway.security.MapsRoutes.classify(alias + entry.getKey());
                assertNotNull(policy, entry.getKey());
                assertEquals("edge", policy.backend());
                assertFalse(policy.publicRoute());
                assertEquals(entry.getValue(), policy.methods());
            }
            var published = com.fooddelivery.apigateway.security.MapsRoutes.classify(alias + metadata + "public/" + id);
            assertNotNull(published);
            assertEquals("edge", published.backend());
            assertEquals("public-metadata", published.operation());
            assertTrue(published.publicRoute());
            assertEquals(java.util.Set.of(get), published.methods());
            for (String path : List.of(metadata + "records/" + id + "/approve", metadata + "public/not-a-uuid",
                    metadata + "public/" + id + "/history", metadata + "records/" + id + "/01", inspect + "areas/" + id + "/01")) {
                assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(alias + path), path);
            }
        }
    }

    @Test void privateRoutingAdmitsOnlyImplementedPrivateMethods() {
        var get = org.springframework.http.HttpMethod.GET;var post = org.springframework.http.HttpMethod.POST;var put = org.springframework.http.HttpMethod.PUT;
        String id = "11111111-1111-4111-8111-111111111111";
        var declared = new java.util.LinkedHashMap<String,java.util.Set<org.springframework.http.HttpMethod>>();
        declared.put("/api/v1/spatial/relations",java.util.Set.of(post));
        declared.put("/api/v1/saved-routes",java.util.Set.of(post));
        declared.put("/api/v1/saved-routes/"+id,java.util.Set.of(get));
        declared.put("/api/v1/saved-routes/"+id+"/revisions/1",java.util.Set.of(get));
        for(String edit:List.of("name","path","archive","restore","annotations","annotations/"+id+"/remove")) declared.put("/api/v1/saved-routes/"+id+"/"+edit,java.util.Set.of(post));
        for(String read:List.of("catalog","catalog/"+id,"sections/"+id)) declared.put("/api/v1/roads/"+read,java.util.Set.of(get));
        for(String write:List.of("preview","sections")) declared.put("/api/v1/roads/"+write,java.util.Set.of(post));
        declared.put("/api/v1/road-metadata/records",java.util.Set.of(post));
        declared.put("/api/v1/road-metadata/records/"+id,java.util.Set.of(get,put));
        declared.put("/api/v1/road-metadata/templates",java.util.Set.of(get,post));
        declared.put("/api/v1/road-metadata/templates/"+id,java.util.Set.of(put));
        declared.put("/api/v1/road-metadata/templates/"+id+"/retire",java.util.Set.of(post));
        for(String read:List.of("sections/"+id,"records/"+id+"/history","records/"+id+"/1","templates/"+id+"/1")) declared.put("/api/v1/road-metadata/"+read,java.util.Set.of(get));
        for(String kind:List.of("saved-routes","road-sections")) declared.put("/api/v1/inspection/"+kind+"/"+id+"/1",java.util.Set.of(get));
        String selection="a".repeat(64);
        declared.put("/api/v1/inspection/routes/"+selection+"/0",java.util.Set.of(get));
        declared.put("/api/v1/road-metadata/records/"+id+"/publish",java.util.Set.of(post));
        declared.put("/api/v1/road-metadata/records/"+id+"/withdraw",java.util.Set.of(post));
        for (String alias : List.of("", "/maps-service")) {
            var publicInspection = com.fooddelivery.apigateway.security.MapsRoutes.classify(
                    alias+"/api/v1/inspection/public-routes/"+selection+"/0");
            assertNotNull(publicInspection);
            assertEquals("edge", publicInspection.backend());
            assertTrue(publicInspection.publicRoute());
            assertEquals(java.util.Set.of(get), publicInspection.methods());
        }
        declared.put("/api/v1/inspection/saved-route-roads/"+id+"/1",java.util.Set.of(get));
        for(String alias:List.of("","/maps-service")) {
            for(var entry:declared.entrySet()) {
                var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(alias+entry.getKey());
                assertNotNull(policy,entry.getKey());assertEquals("edge",policy.backend());assertFalse(policy.publicRoute());assertEquals(entry.getValue(),policy.methods());
            }
            for(String refused:List.of("/api/v1/saved-routes-extra","/api/v1/saved-routes/"+id+"/revisions/01","/api/v1/roads/catalog/all","/api/v1/roads/sections/"+id+"/approve","/api/v1/road-metadata/records/"+id+"/approve","/api/v1/inspection/saved-routes-roads/"+id+"/1","/api/v1/inspection/routes/"+selection+"/3","/api/v1/inspection/routes/not-a-selection/0","/api/v1/inspection/saved-route-roads/"+id+"/01","/api/v1/inspection/road-sections/"+id+"/01")) assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(alias+refused),refused);
        }
    }

    @Test void publicDiscoveryAdmitsOnlyTypedReadPaths() {
        for(String prefix:List.of("","/maps-service")) {
            for(String path:List.of("search","reverse","pois","features/osm:node:101","features/osm:way:7","features/osm:relation:1")) {
                var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(prefix+"/api/v1/"+path);
                assertNotNull(policy,path);assertEquals("postal",policy.backend());assertTrue(policy.publicRoute());assertEquals(java.util.Set.of(org.springframework.http.HttpMethod.GET),policy.methods());
            }
            for(String path:List.of("search-extra","features/osm:user:1","features/osm:node:0","features/osm:node:01","features/osm:node:12345678901234567890","features/osm:node:101/more"))
                assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(prefix+"/api/v1/"+path),path);
        }
    }


    @Test void exportJobsAreExactPrivateOperations() {
        String id="11111111-1111-4111-8111-111111111111";
        for(String alias:List.of("","/maps-service")){
            for(var entry:java.util.Map.of("/api/v1/resources/"+id+"/export-jobs",org.springframework.http.HttpMethod.POST,
                    "/api/v1/resource-jobs",org.springframework.http.HttpMethod.GET,
                    "/api/v1/resource-jobs/"+id,org.springframework.http.HttpMethod.GET,
                    "/api/v1/resource-jobs/"+id+"/execute",org.springframework.http.HttpMethod.POST,
                    "/api/v1/resource-jobs/"+id+"/download",org.springframework.http.HttpMethod.GET).entrySet()){
                var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(alias+entry.getKey());
                assertNotNull(policy,entry.getKey());assertEquals("edge",policy.backend());assertFalse(policy.publicRoute());assertEquals(java.util.Set.of(entry.getValue()),policy.methods());
            }
            var machine=com.fooddelivery.apigateway.security.MapsRoutes.classify(alias+"/api/v1/machine/resource-jobs/"+id+"/execute");
            assertNotNull(machine);assertEquals("machine-job-execute",machine.operation());assertEquals("edge",machine.backend());
            assertFalse(machine.publicRoute());assertEquals(java.util.Set.of(org.springframework.http.HttpMethod.POST),machine.methods());
            for(String path:List.of("/api/v1/resource-jobs/","/api/v1/resource-jobs-extra","/api/v1/resource-jobs/"+id+"/execute/extra","/api/v1/resource-jobs/"+id+"/download/extra","/api/v1/machine/resource-jobs/"+id+"/download","/api/v1/machine/resource-jobs/not-a-uuid/execute","/api/v1/resource-jobs/not-a-uuid/execute"))assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(alias+path),path);
        }
    }

    @Test void resourceGrantsUseOnlyExactPrivateWritePaths() {
        String id = "11111111-1111-4111-8111-111111111111";
        for (String alias : List.of("", "/maps-service")) {
            String base = alias + "/api/v1/resource-grants/";
            for (String kind : List.of("area", "area_metadata", "saved_route", "metadata")) {
                var policy = com.fooddelivery.apigateway.security.MapsRoutes.classify(base + kind + "/" + id);
                assertNotNull(policy);
                assertEquals("edge", policy.backend());
                assertFalse(policy.publicRoute());
                assertEquals(java.util.Set.of(org.springframework.http.HttpMethod.POST), policy.methods());
            }
            for (String path : List.of("area/not-a-uuid", "road/" + id, "area/" + id + "/more", "area_metadata/not-a-uuid", "area-metadata/" + id)) {
                assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(base + path));
                assertTrue(com.fooddelivery.apigateway.security.MapsRoutes.reserved(base + path));
            }
        }
    }

    @Test void terrainReadsAreExactPublicOperations() {
        String hash="a".repeat(64);
        for(String alias:List.of("","/maps-service")){
            for(String path:List.of("/terrain/capabilities.json","/terrain/"+hash+"/dem/12/2930/1899.png","/terrain/"+hash+"/hillshade/14/11723/7596.png")){
                var policy=com.fooddelivery.apigateway.security.MapsRoutes.classify(alias+path);assertNotNull(policy,path);assertEquals("edge",policy.backend());assertTrue(policy.publicRoute());assertEquals(java.util.Set.of(org.springframework.http.HttpMethod.GET,org.springframework.http.HttpMethod.HEAD),policy.methods());
            }
            for(String path:List.of("/terrain/config.json","/terrain/"+hash+"/raster.f32","/terrain/"+hash+"/dem/15/1/1.png","/terrain/"+hash+"/dem/12/01/1.png","/terrain/capabilities.json/extra"))assertNull(com.fooddelivery.apigateway.security.MapsRoutes.classify(alias+path),path);
        }
    }
}
