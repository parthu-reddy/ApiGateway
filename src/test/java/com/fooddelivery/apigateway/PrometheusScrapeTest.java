package com.fooddelivery.apigateway;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import com.fooddelivery.common.security.IdentityTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gateway is the internet-facing edge, so unlike the internal services it never serves /actuator/prometheus to an
 * anonymous caller: ActuatorAccessFilter answers 401 unless the read carries a fresh SERVICE signature. Both halves run
 * on a real port through the gateway's whole WebFilter chain (PrometheusRegistry_2026-10-17): the unsigned read fails
 * when the filter admits it, the signed read fails with 404 without the registry.
 */
// Boot's test support swaps every metrics exporter for a SimpleMeterRegistry; keep the real ones, as Dev runs them.
@org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability(tracing = false)
class PrometheusScrapeTest extends GatewayApplicationFixture {

    @LocalServerPort
    private int port;

    /** The signer ActuatorAccessFilter verifies with: a signature only this context's key produces. */
    @Autowired
    private IdentityTokenService signatures;

    private HttpResponse<String> scrape(HttpRequest.Builder request) throws Exception {
        return HttpClient.newHttpClient().send(request.GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest.Builder prometheus() {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/actuator/prometheus"));
    }

    @Test
    void anUnsignedScrapeIsRefused() throws Exception {
        HttpResponse<String> response = scrape(prometheus());
        assertEquals(401, response.statusCode(),
                () -> "unsigned scrape of /actuator/prometheus answered " + response.statusCode() + ", expected 401");
    }

    @Test
    void aSignedServiceScrapeIsServed() throws Exception {
        long issued = System.currentTimeMillis();
        HttpResponse<String> response = scrape(prometheus()
                .header("X-User-Id", "prometheus-scrape-test")
                .header("X-User-Roles", "SERVICE")
                .header("X-Issued-At", Long.toString(issued))
                .header("X-Identity-Signature", signatures.sign("prometheus-scrape-test", "SERVICE", null, null, issued)));
        String head = response.body().length() > 300 ? response.body().substring(0, 300) : response.body();
        assertEquals(200, response.statusCode(),
                () -> "scrape of /actuator/prometheus answered " + response.statusCode() + ": " + head);
        assertTrue(response.body().contains("jvm_memory_used_bytes"),
                () -> "scrape of /actuator/prometheus answered 200 without a jvm_memory_used_bytes sample: " + head);
    }
}
