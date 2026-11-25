package com.fooddelivery.apigateway.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The packaged maps profile, booted as the new server runs it: no Config Server file, no Eureka, an unreachable Redis
 * and nothing mocked. Backends are real listeners, the edge one requiring a client certificate.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "spring.cloud.config.enabled=false", "spring.data.redis.host=redis.invalid", "MAPS_GATEWAY_MANAGEMENT_PORT=0"})
@ActiveProfiles("maps")
class MapsStandaloneProfileTest {
    private static final String ORIGIN = "https://maps.test";
    private static final String PASSWORD = "fixture-only";
    private static final Map<String, HttpExchangeRecord> seen = new ConcurrentHashMap<>();
    private static final java.util.Queue<String> areaBodies = new java.util.concurrent.ConcurrentLinkedQueue<>();
    private record HttpExchangeRecord(String path, Map<String, java.util.List<String>> headers, boolean clientCertificate) {}
    private static HttpServer plain;
    private static HttpsServer edge;
    private static Path material;
    private static final String HMAC_SECRET = "security.identity.hmac-secret";
    private static String inheritedSecret;

    @LocalServerPort int port;
    @LocalManagementPort int management;
    @Autowired ApplicationContext context;

    private static void answer(HttpExchange exchange, String backend, boolean certificate) throws java.io.IOException {
        seen.put(backend, new HttpExchangeRecord(exchange.getRequestURI().getPath(), Map.copyOf(exchange.getRequestHeaders()), certificate));
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        byte[] body = ("{\"backend\":\"" + backend + "\"}").getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) { out.write(body); }
    }

    private static void keytool(String... arguments) throws Exception {
        var command = new java.util.ArrayList<>(java.util.List.of(Path.of(System.getProperty("java.home"), "bin", "keytool").toString()));
        command.addAll(java.util.List.of(arguments));
        var process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertEquals(0, process.waitFor(), "keytool failed");
    }

    @DynamicPropertySource
    static void servers(DynamicPropertyRegistry registry) throws Exception {
        // The parent POM gives every test JVM this, which no deployment has: leaving it in hid a failed start once.
        inheritedSecret = System.clearProperty(HMAC_SECRET);
        material = Files.createTempDirectory("maps-gateway-profile");
        File store = material.resolve("fixture.p12").toFile(), certificate = material.resolve("fixture.pem").toFile();
        keytool("-genkeypair", "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048", "-validity", "1", "-storetype", "PKCS12",
                "-keystore", store.getPath(), "-storepass", PASSWORD, "-dname", "CN=localhost", "-ext", "san=dns:localhost");
        keytool("-exportcert", "-rfc", "-alias", "fixture", "-keystore", store.getPath(), "-storepass", PASSWORD, "-file", certificate.getPath());
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var in = new FileInputStream(store)) { keys.load(in, PASSWORD.toCharArray()); }
        var managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keys, PASSWORD.toCharArray());
        var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(keys);
        var tls = SSLContext.getInstance("TLS");
        tls.init(managers.getKeyManagers(), trust.getTrustManagers(), null);

        edge = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        edge.setHttpsConfigurator(new HttpsConfigurator(tls) {
            // Not HttpsParameters.setNeedClientAuth: the JDK then also applies its wantClientAuth=false, which clears it.
            @Override public void configure(HttpsParameters parameters) {
                var required = tls.getDefaultSSLParameters();
                required.setNeedClientAuth(true);
                parameters.setSSLParameters(required);
            }
        });
        // Reads the whole body as Go's io.ReadAll does: a terminated stream is a body the edge would process.
        edge.createContext("/", exchange -> {
            if (!exchange.getRequestURI().getPath().equals("/api/v1/areas")) {
                boolean presented;
                try { presented = ((com.sun.net.httpserver.HttpsExchange) exchange).getSSLSession().getPeerCertificates().length > 0; }
                catch (javax.net.ssl.SSLPeerUnverifiedException ex) { presented = false; }
                answer(exchange, "edge", presented);
                return;
            }
            long read = 0;
            String outcome;
            try (var in = exchange.getRequestBody()) {
                byte[] buffer = new byte[1 << 16];
                for (int n; (n = in.read(buffer)) >= 0;) read += n;
                outcome = "terminated";
            } catch (java.io.IOException ex) {
                outcome = "incomplete";
            }
            areaBodies.add(outcome + ":" + read);
            // Like the Go edge, answer either outcome (400 for the unterminated JSON or for a cut stream) if the peer is still there.
            try {
                exchange.getResponseHeaders().set("X-Fixture-Hop", "edge");
                exchange.sendResponseHeaders(400, -1);
            } catch (java.io.IOException peerGone) {
                // The gateway may already have closed the connection.
            }
            exchange.close();
        });
        edge.start();
        plain = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        plain.createContext("/", exchange -> answer(exchange, "plain", false));
        plain.start();

        String local = "http://localhost:" + plain.getAddress().getPort();
        registry.add("MAPS_PUBLIC_ORIGIN", () -> ORIGIN);
        registry.add("MAPS_GATEWAY_TRUSTED_PROXIES", () -> "192.168.0.0/16");
        registry.add("MAPS_EDGE_URI", () -> "https://localhost:" + edge.getAddress().getPort());
        for (String backend : java.util.List.of("MAPS_PUBLIC_URI", "MAPS_ASSETS_URI", "MAPS_POSTAL_URI", "MAPS_ROUTING_URI")) registry.add(backend, () -> local);
        registry.add("MAPS_GATEWAY_TLS_KEY_STORE", store.toURI()::toString);
        registry.add("MAPS_GATEWAY_TLS_KEY_STORE_PASSWORD", () -> PASSWORD);
        registry.add("MAPS_GATEWAY_TLS_TRUST_CERTIFICATES", certificate.toURI()::toString);
    }

    @AfterAll
    static void stop() throws Exception {
        if (inheritedSecret != null) System.setProperty(HMAC_SECRET, inheritedSecret);
        plain.stop(0);
        edge.stop(0);
        try (var files = Files.walk(material)) { files.sorted(java.util.Comparator.reverseOrder()).forEach(path -> path.toFile().delete()); }
    }

    private HttpResponse<String> send(int target, String method, String path, Map<String, String> headers) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + target + path))
                .method(method, (method.equals("POST") || method.equals("PUT")) ? HttpRequest.BodyPublishers.ofString("{}") : HttpRequest.BodyPublishers.noBody());
        headers.forEach(request::header);
        return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static final Map<String, String> CREDENTIALS = Map.of("Cookie", "maps=secret", "Authorization", "Bearer secret", "X-CSRF-Token", "secret");

    @Test void startsWithoutAnyFoodDeliveryInfrastructure() {
        assertFalse(context.containsBean("eurekaClient"));
        assertTrue(context.containsBean("mapsRoutes"));
    }

    @Test void healthIsServedOnlyOnTheManagementPortAndNeedsNoRedis() throws Exception {
        assertEquals(200, send(management, "GET", "/actuator/health", Map.of()).statusCode());
        assertEquals(404, send(port, "GET", "/actuator/health", Map.of()).statusCode());
    }

    @Test void plainBackendIsReachedAndReceivesNoCredentials() throws Exception {
        var response = send(port, "GET", "/api/v1/countries/IN/postal-codes/560001", CREDENTIALS);
        assertEquals(200, response.statusCode(), response.body());
        assertEquals("{\"backend\":\"plain\"}", response.body());
        var received = seen.get("plain");
        for (String header : CREDENTIALS.keySet()) assertNull(received.headers().get(header), header + " reached a plain http backend");
    }

    @Test void filteredTilesUseThePublicBackendWithoutCredentials() throws Exception {
        String path = "/public/" + "a".repeat(64) + "/filtered/14/11723/7596.mvt";
        var response = send(port, "GET", path + "?layers=roads,pois", CREDENTIALS);
        assertEquals(200, response.statusCode(), response.body());
        assertEquals("{\"backend\":\"plain\"}", response.body());
        var received = seen.get("plain");
        assertEquals(path, received.path());
        for (String header : CREDENTIALS.keySet()) assertNull(received.headers().get(header));
        assertEquals(404, send(port, "GET", path + "/extra", Map.of()).statusCode());
    }

    @Test void edgeIsReachedOverMutualTlsWithTheSessionCookie() throws Exception {
        var response = send(port, "GET", "/api/v1/maps-session/session", Map.of("Cookie", "maps=secret"));
        assertEquals(200, response.statusCode(), response.body());
        var received = seen.get("edge");
        assertTrue(received.clientCertificate(), "the edge hop must present the gateway's certificate");
        assertEquals(java.util.List.of("maps=secret"), received.headers().get("Cookie"));
    }

    @Test void theBrowserOriginPassesThoughTlsEndedAtTheProxyAndNoOtherOriginDoes() throws Exception {
        var same = send(port, "POST", "/api/v1/maps-session/logout-proof", Map.of("Origin", ORIGIN, "Content-Type", "application/json"));
        assertEquals(200, same.statusCode(), same.body());
        var other = send(port, "POST", "/api/v1/maps-session/logout-proof", Map.of("Origin", "https://other.test", "Content-Type", "application/json"));
        assertEquals(403, other.statusCode(), other.body());
    }

    @Test void frontendLogControllerIsUnavailableOnMaps() throws Exception {
        assertFalse(context.containsBean("frontendLogController"));
        assertEquals(404, send(port, "POST", "/api/logs", Map.of("Content-Type", "application/json")).statusCode());
    }

    @Test void anythingTheMapsContractDoesNotDeclareIsRefused() throws Exception {
        var checks = new java.util.ArrayList<org.junit.jupiter.api.function.Executable>();
        checks.add(()->assertFalse(context.containsBean("indexController")));
        for (String path : java.util.List.of("/api/v1/auth/session", "/", "/index.html", "/v3/api-docs", "/swagger-ui.html", "/webjars/swagger-ui/index.html")) {
            checks.add(()->assertEquals(404, send(port, "GET", path, Map.of()).statusCode(), path));
        }
        checks.add(()->assertEquals(404, send(port, "HEAD", "/", Map.of()).statusCode()));
        org.junit.jupiter.api.Assertions.assertAll(checks);
    }
    @Test void privateSavedAreaPutUsesTheDeclaredOriginAndCanonicalEdgeHop() throws Exception {
        String canonical = "/api/v1/areas/11111111-1111-4111-8111-111111111111";
        var headers = Map.of("Origin", ORIGIN, "Content-Type", "application/json", "Cookie", "maps=opaque",
                "X-CSRF-Token", "fixture-proof", "If-Match", "fixture-etag", "Idempotency-Key", "fixture-key");
        var response = send(port, "PUT", "/maps-service" + canonical, headers);
        assertEquals(200, response.statusCode());
        var received = seen.get("edge");assertEquals(canonical, received.path());assertTrue(received.clientCertificate());
        for (String header : java.util.List.of("Cookie","X-CSRF-Token","If-Match","Idempotency-Key")) {
            assertEquals(java.util.List.of(headers.get(header)), received.headers().entrySet().stream()
                    .filter(entry -> entry.getKey().equalsIgnoreCase(header)).findFirst().orElseThrow().getValue(), header);
        }
        var other = new java.util.HashMap<>(headers);other.put("Origin", "https://other.test");
        assertEquals(403, send(port, "PUT", canonical, other).statusCode());
    }

    private record RawResponse(int status, Map<String, String> headers, String body) {}

    /** A chunked area upload of {@code size} bytes over a raw socket, reading the response while it is still uploading. */
    private RawResponse chunkedAreaUpload(long size) throws Exception {
        try (var socket = new java.net.Socket("localhost", port)) {
            socket.setSoTimeout(30_000);
            var out = socket.getOutputStream();
            var head = "POST /api/v1/areas HTTP/1.1\r\nHost: localhost\r\nOrigin: " + ORIGIN + "\r\nContent-Type: application/json\r\n"
                    + "Cookie: maps=opaque\r\nX-CSRF-Token: fixture-proof\r\nTransfer-Encoding: chunked\r\n\r\n";
            out.write(head.getBytes(StandardCharsets.US_ASCII));
            var upload = new Thread(() -> {
                try {
                    byte[] chunk = new byte[1 << 16];
                    java.util.Arrays.fill(chunk, (byte) 'a');
                    byte[] prefix = "{\"name\":\"".getBytes(StandardCharsets.US_ASCII);
                    System.arraycopy(prefix, 0, chunk, 0, prefix.length);
                    for (long left = size; left > 0;) {
                        int n = (int) Math.min(left, chunk.length);
                        out.write((Integer.toHexString(n) + "\r\n").getBytes(StandardCharsets.US_ASCII));
                        out.write(chunk, 0, n);
                        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
                        left -= n;
                        if (left == size - n) java.util.Arrays.fill(chunk, 0, prefix.length, (byte) 'a');
                    }
                    out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (java.io.IOException refusedWhileUploading) {
                    // The gateway may stop reading once it has answered; the response is still read below.
                }
            });
            upload.start();
            var in = new java.io.BufferedInputStream(socket.getInputStream());
            String status = readLine(in);
            var headers = new java.util.TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
            for (String line; !(line = readLine(in)).isEmpty();) headers.put(line.substring(0, line.indexOf(':')), line.substring(line.indexOf(':') + 1).trim());
            byte[] body = in.readNBytes(Integer.parseInt(headers.getOrDefault("Content-Length", "0")));
            upload.join(30_000);
            return new RawResponse(Integer.parseInt(status.split(" ")[1]), headers, new String(body, StandardCharsets.UTF_8));
        }
    }

    private static String readLine(java.io.InputStream in) throws java.io.IOException {
        var line = new StringBuilder();
        for (int c; (c = in.read()) != '\n';) { if (c < 0) throw new java.io.EOFException("response ended: " + line); if (c != '\r') line.append((char) c); }
        return line.toString();
    }

    private static String awaitAreaBody() throws InterruptedException {
        for (int i = 0; i < 100; i++) { String outcome = areaBodies.poll(); if (outcome != null) return outcome; Thread.sleep(100); }
        return "none";
    }

    /**
     * A chunked area body that crosses the gateway's limit after earlier buffers were forwarded must reach the edge as an
     * aborted stream, never as a terminated prefix it would process; the client gets the gateway's own 413. The exact-limit
     * upload is the control showing this edge does observe a terminated body.
     */
    @Test void streamedAreaOverflowNeverReachesTheEdgeAsATerminatedBody() throws Exception {
        long limit = 10_000_000;
        areaBodies.clear();
        var exact = chunkedAreaUpload(limit);
        assertEquals(400, exact.status(), exact.body());
        assertEquals("edge", exact.headers().get("X-Fixture-Hop"));
        assertEquals("terminated:" + limit, awaitAreaBody());
        for (int trial = 0; trial < 3; trial++) {
            var over = chunkedAreaUpload(limit + 100);
            String edgeSaw = awaitAreaBody();
            assertTrue(edgeSaw.startsWith("incomplete:"), "trial " + trial + ": the edge received " + edgeSaw);
            assertEquals(413, over.status(), "trial " + trial + ": " + over.body());
            assertNull(over.headers().get("X-Fixture-Hop"), "trial " + trial + ": the edge's answer reached the client");
            assertEquals("{\"code\":\"PAYLOAD_TOO_LARGE\"}", over.body());
        }
    }

    @Test void privateExportJobListUsesTheMtlsEdgeAtBothBases() throws Exception {
        String canonical = "/api/v1/resource-jobs";
        for (String base : java.util.List.of("", "/maps-service")) {
            var response = send(port, "GET", base + canonical, Map.of("Origin", ORIGIN, "Cookie", "maps=opaque"));
            assertEquals(200, response.statusCode(), response.body());
            assertEquals("{\"backend\":\"edge\"}", response.body());
            var received = seen.get("edge");
            assertEquals(canonical, received.path());
            assertTrue(received.clientCertificate());
            assertEquals(java.util.List.of("maps=opaque"), received.headers().get("Cookie"));
            assertEquals(405, send(port, "POST", base + canonical, Map.of("Origin", ORIGIN)).statusCode());
            assertEquals(403, send(port, "GET", base + canonical, Map.of("Origin", "https://other.test")).statusCode());
        }
    }

}
