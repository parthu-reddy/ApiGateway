package com.fooddelivery.apigateway.security;

import java.util.Set;
import org.springframework.http.HttpMethod;

/** Only source-backed operations are admitted; spec candidates and internal/engine paths stay closed. */
public final class MapsRoutes {
    public record Policy(String backend, String operation, boolean publicRoute, Set<HttpMethod> methods) {}
    private static final Set<HttpMethod> READ = Set.of(HttpMethod.GET);
    private static final Set<HttpMethod> ASSET = Set.of(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS);
    private static final Set<HttpMethod> POST = Set.of(HttpMethod.POST);
    private static final String UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final String REVISION = "[1-9][0-9]{0,18}";
    private static final String HASH = "[0-9a-f]{64}";
    private MapsRoutes() {}
    public static String canonical(String path) { return path.startsWith("/maps-service/") ? path.substring(13) : path; }
    public static boolean reserved(String path) {
        String p = canonical(path);
        return path.startsWith("/maps-service/") || p.startsWith("/api/v1/maps-session")
                || p.startsWith("/api/v1/resources") || p.startsWith("/api/v1/resource-jobs") || p.startsWith("/api/v1/machine/resource-jobs");
    }
    public static Policy classify(String path) {
        String p = canonical(path);
        if (p.equals("/api/v1/maps-session/session")||p.equals("/api/v1/maps-session/logout-status")) return new Policy("edge", "session-status", false, READ);
        if (p.matches("/api/v1/maps-session/(otp|login|refresh|activity|logout|logout-proof)"))
            return new Policy("edge", "session-" + p.substring(p.lastIndexOf('/')+1), false, POST);
        if (p.equals("/api/v1/spatial/relations")) return new Policy("edge", "spatial-relations", false, POST);
        if (p.equals("/api/v1/areas")) return new Policy("edge", "area-collection", false, Set.of(HttpMethod.GET, HttpMethod.POST));
        if (p.equals("/api/v1/areas/at-point")) return new Policy("edge", "area-boundary-matches", false, READ);
        if (p.matches("/api/v1/areas/overlay/(?:[0-9]|1[0-8])/(?:0|[1-9][0-9]{0,5})/(?:0|[1-9][0-9]{0,5})"))
            return new Policy("edge", "area-overlay", false, READ);
        if (p.matches("/api/v1/areas/"+UUID)) return new Policy("edge", "area-record", false, Set.of(HttpMethod.GET, HttpMethod.PUT));
        if (p.matches("/api/v1/areas/"+UUID+"/(?:history|export)")) return new Policy("edge", "area-read", false, READ);
        if (p.matches("/api/v1/areas/"+UUID+"/(?:archive|restore)")) return new Policy("edge", "area-lifecycle", false, POST);
        if (p.matches("/api/v1/areas(?:/"+UUID+")?/repair")) return new Policy("edge", "area-repair", false, POST);
        if (p.matches("/api/v1/area-editor/(?:import|validate|repair)")) return new Policy("edge", "area-editor", false, POST);
        if (p.equals("/api/v1/metadata/records") || p.matches("/api/v1/metadata/templates/"+UUID+"/retire"))
            return new Policy("edge", "area-metadata", false, POST);
        if (p.equals("/api/v1/metadata/templates"))
            return new Policy("edge", "area-metadata", false, Set.of(HttpMethod.GET, HttpMethod.POST));
        if (p.matches("/api/v1/metadata/records/"+UUID))
            return new Policy("edge", "area-metadata", false, Set.of(HttpMethod.GET, HttpMethod.PUT));
        if (p.matches("/api/v1/metadata/templates/"+UUID))
            return new Policy("edge", "area-metadata", false, Set.of(HttpMethod.PUT));
        if (p.matches("/api/v1/metadata/(?:areas/"+UUID+"|records/"+UUID+"/(?:history|"+REVISION+")|templates/"+UUID+"/"+REVISION+")"))
            return new Policy("edge", "area-metadata", false, READ);
        if (p.matches("/api/v1/inspection/areas/"+UUID+"/"+REVISION))
            return new Policy("edge", "area-inspection", false, READ);
        if (p.equals("/api/v1/saved-routes")) return new Policy("edge", "routing-mutation", false, POST);
        if (p.matches("/api/v1/saved-routes/"+UUID+"(?:/revisions/"+REVISION+")?"))
            return new Policy("edge", "saved-route-read", false, READ);
        if (p.matches("/api/v1/saved-routes/"+UUID+"/annotations"))
            return new Policy("edge", "routing-annotation", false, POST);
        if (p.matches("/api/v1/saved-routes/"+UUID+"/(?:name|path|archive|restore|annotations/"+UUID+"/remove)"))
            return new Policy("edge", "routing-mutation", false, POST);
        if (p.matches("/api/v1/roads/(?:catalog(?:/"+UUID+")?|sections/"+UUID+")"))
            return new Policy("edge", "road-read", false, READ);
        if (p.matches("/api/v1/roads/(?:preview|sections)")) return new Policy("edge", "routing-mutation", false, POST);
        if (p.equals("/api/v1/road-metadata/records") || p.matches("/api/v1/road-metadata/templates/"+UUID+"/retire"))
            return new Policy("edge", "routing-metadata", false, POST);
        if (p.equals("/api/v1/road-metadata/templates")) return new Policy("edge", "routing-metadata", false, Set.of(HttpMethod.GET,HttpMethod.POST));
        if (p.matches("/api/v1/road-metadata/records/"+UUID)) return new Policy("edge", "routing-metadata", false, Set.of(HttpMethod.GET,HttpMethod.PUT));
        if (p.matches("/api/v1/road-metadata/templates/"+UUID)) return new Policy("edge", "routing-metadata", false, Set.of(HttpMethod.PUT));
        if (p.matches("/api/v1/road-metadata/(?:sections/"+UUID+"|records/"+UUID+"/(?:history|"+REVISION+")|templates/"+UUID+"/"+REVISION+")"))
            return new Policy("edge", "routing-metadata", false, READ);
        if (p.matches("/api/v1/inspection/(?:saved-routes|saved-route-roads|road-sections)/"+UUID+"/"+REVISION)
                || p.matches("/api/v1/inspection/routes/"+HASH+"/[0-2]"))
            return new Policy("edge", "routing-inspection", false, READ);
        if (p.equals("/api/v1/resources") || p.equals("/api/v1/search/resources")) return new Policy("edge", "resource-list", false, READ);
        if (p.matches("/api/v1/resources/"+UUID+"(?:/(?:history|export))?")) return new Policy("edge", "resource-read", false, READ);
        if (p.matches("/api/v1/resources/"+UUID+"/tiles/[0-9]+/[0-9]+/[0-9]+\\.mvt")) return new Policy("edge", "resource-tile", false, READ);
        if (p.matches("/api/v1/resources/"+UUID+"/export-jobs")) return new Policy("edge", "resource-export-job", false, POST);
        if (p.matches("/api/v1/resource-jobs/"+UUID+"/execute")) return new Policy("edge", "resource-job-execute", false, POST);
        if (p.matches("/api/v1/resource-jobs/"+UUID+"(?:/download)?")) return new Policy("edge", "resource-job", false, READ);
        if (p.equals("/api/v1/search") || p.equals("/api/v1/reverse") || p.equals("/api/v1/pois") || p.matches("/api/v1/features/osm:(?:node|way|relation):[1-9][0-9]{0,18}"))
            return new Policy("postal", "discovery-read", true, READ);
        if (p.equals("/terrain/capabilities.json") || p.matches("/terrain/"+HASH+"/(?:dem|hillshade)/1[2-4]/(?:0|[1-9][0-9]{0,4})/(?:0|[1-9][0-9]{0,4})\\.png"))
            return new Policy("edge", "terrain-read", true, Set.of(HttpMethod.GET,HttpMethod.HEAD));
        if (p.equals("/api/v1/capabilities")) return new Policy("edge", "capabilities", true, READ);
        if (p.matches("/public/"+HASH+"/(?:basemap\\.(?:json|pmtiles)|schema\\.json|tiles/[0-9]+/[0-9]+/[0-9]+\\.mvt)"))
            return new Policy("public", "public-snapshot", true, ASSET);
        if (p.matches("/assets/"+HASH+"/(?:release\\.json|styles/(?:streets|dark)\\.json|fonts/(?:NotoSans(?:Devanagari|Kannada)?-Regular\\.ttf|OFL\\.txt|font-lock\\.json)|glyphs/(?:0-255|2304-2559|3072-3327)\\.pbf|sprites/poi(?:@2x)?\\.(?:png|json)|schema\\.json|capabilities\\.json|ATTRIBUTION\\.txt)"))
            return new Policy("assets", "map-asset", true, ASSET);
        if (p.matches("/assets/"+HASH+"/glyphs/Noto Sans Regular,Noto Sans Devanagari Regular,Noto Sans Kannada Regular/(?:0-255|2304-2559|3072-3327)\\.pbf"))
            return new Policy("assets", "map-glyph", true, ASSET);
        if (p.matches("/api/v1/countries/IN/postal-codes/[0-9]{6}(?:/(?:geometry|neighbors))?")
                || p.equals("/api/v1/countries/IN/postal-codes/at-point") || p.equals("/api/v1/postal-codes/at-point"))
            return new Policy("postal", "postal-read", true, READ);
        if (p.equals("/api/v1/routes/analyses/capabilities")) return new Policy("routing", "analysis-capabilities", true, READ);
        if (p.matches("/api/v1/routes/(?:matrix|isochrones|match|optimise|elevation)"))
            return new Policy("routing", "analysis-" + p.substring(p.lastIndexOf('/')+1), true, POST);
        if (p.equals("/api/v1/routes/capabilities")) return new Policy("routing", "route-capabilities", true, READ);
        if (p.equals("/api/v1/routes/directions")) return new Policy("routing", "route-directions", true, POST);
        if (p.equals("/api/v1/routes/calculate")) return new Policy("routing", "route-calculate", true, POST);
        return null;
    }
}
