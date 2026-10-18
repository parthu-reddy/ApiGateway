package com.fooddelivery.apigateway;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gateway's actuator lives on its own management port, which compose never publishes: Prometheus scrapes it
 * anonymously on the compose network like every internal service, and the internet-facing edge port serves no
 * actuator at all (GatewayScrapeAndAlerting_2026-10-18 Phase 1). Both ports are real servers here, behind the
 * gateway's whole WebFilter chain and the real Deployment/api-gateway.yml.
 */
// Boot's test support swaps every metrics exporter for a SimpleMeterRegistry; keep the real ones, as Dev runs them.
@org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability(tracing = false)
class PrometheusScrapeTest extends GatewayApplicationFixture {

    @LocalServerPort
    private int edge;

    @LocalManagementPort
    private int management;

    private HttpResponse<String> call(String method, int port, String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, HttpRequest.BodyPublishers.noBody()).build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void theManagementPortServesAnAnonymousScrapeWithTheStaleTokenSeries() throws Exception {
        HttpResponse<String> response = call("GET", management, "/actuator/prometheus");
        String head = response.body().length() > 300 ? response.body().substring(0, 300) : response.body();
        assertEquals(200, response.statusCode(),
                () -> "anonymous management-port scrape of /actuator/prometheus answered " + response.statusCode() + ": " + head);
        assertTrue(response.body().contains("jvm_memory_used_bytes"),
                () -> "management-port scrape answered 200 without a jvm_memory_used_bytes sample: " + head);
        // Registered at startup, so EntitlementStaleTokenSpike's metric exists before the first refusal.
        assertTrue(response.body().lines().anyMatch(l -> l.startsWith("gateway_entitlements_stale_tokens_total ")),
                "management-port scrape has no gateway_entitlements_stale_tokens_total series");
        assertEquals(200, call("GET", management, "/actuator/health").statusCode());
    }

    @Test
    void theEdgeServesNoActuator() throws Exception {
        for (String path : new String[] {"/actuator/prometheus", "/actuator/health", "/actuator/gateway/routes", "/actuator"}) {
            int status = call("GET", edge, path).statusCode();
            assertEquals(404, status, () -> "edge GET " + path + " answered " + status + ", expected 404");
        }
    }

    @Test
    void theManagementPortRefusesActuatorWrites() throws Exception {
        assertEquals(405, call("POST", management, "/actuator/gateway/refresh").statusCode());
        assertEquals(405, call("DELETE", management, "/actuator/gateway/routes/any").statusCode());
    }
}
