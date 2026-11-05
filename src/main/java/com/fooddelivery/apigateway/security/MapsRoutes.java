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
        if (p.equals("/api/v1/resources") || p.equals("/api/v1/search/resources")) return new Policy("edge", "resource-list", false, READ);
        if (p.matches("/api/v1/resources/"+UUID+"(?:/(?:history|export))?")) return new Policy("edge", "resource-read", false, READ);
        if (p.matches("/api/v1/resources/"+UUID+"/tiles/[0-9]+/[0-9]+/[0-9]+\\.mvt")) return new Policy("edge", "resource-tile", false, READ);
        if (p.matches("/api/v1/resources/"+UUID+"/export-jobs")) return new Policy("edge", "resource-export-job", false, POST);
        if (p.matches("/api/v1/resource-jobs/"+UUID)) return new Policy("edge", "resource-job", false, READ);
        if (p.equals("/api/v1/capabilities")) return new Policy("edge", "capabilities", true, READ);
        if (p.matches("/public/"+HASH+"/(?:basemap\\.(?:json|pmtiles)|schema\\.json|tiles/[0-9]+/[0-9]+/[0-9]+\\.mvt)"))
            return new Policy("public", "public-snapshot", true, ASSET);
        if (p.matches("/assets/"+HASH+"/(?:styles/(?:streets|dark)\\.json|fonts/(?:NotoSans(?:Devanagari|Kannada)?-Regular\\.ttf|OFL\\.txt|font-lock\\.json)|glyphs/(?:0-255|2304-2559|3072-3327)\\.pbf|sprites/poi(?:@2x)?\\.(?:png|json)|schema\\.json|capabilities\\.json|ATTRIBUTION\\.txt)"))
            return new Policy("assets", "map-asset", true, ASSET);
        if (p.matches("/assets/"+HASH+"/glyphs/Noto Sans Regular,Noto Sans Devanagari Regular,Noto Sans Kannada Regular/(?:0-255|2304-2559|3072-3327)\\.pbf"))
            return new Policy("assets", "map-glyph", true, ASSET);
        if (p.matches("/api/v1/countries/IN/postal-codes/[0-9]{6}(?:/(?:geometry|neighbors))?")
                || p.equals("/api/v1/countries/IN/postal-codes/at-point") || p.equals("/api/v1/postal-codes/at-point"))
            return new Policy("postal", "postal-read", true, READ);
        if (p.equals("/api/v1/routes/capabilities")) return new Policy("routing", "route-capabilities", true, READ);
        if (p.equals("/api/v1/routes/directions")) return new Policy("routing", "route-directions", true, POST);
        if (p.equals("/api/v1/routes/calculate")) return new Policy("routing", "route-calculate", true, POST);
        return null;
    }
}
