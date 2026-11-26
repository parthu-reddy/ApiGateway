package com.fooddelivery.apigateway.config;

import java.net.URI;
import java.util.regex.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;

@lombok.Data
@ConfigurationProperties("gateway.maps")
public class MapsGatewayProperties {
    private boolean enabled;
    /** The browser's origin. Exactly one, and it must match the Maps edge's public_origin. */
    private String publicOrigin;
    private String edgeUri, publicUri, assetsUri, postalUri;
    /** HMAC-SHA256 key (hex, 32 to 64 bytes) for the client pseudonym sent to the edge as X-Maps-Client. The edge keys
     *  its shared heavy-operation budgets on it, so every gateway replica must use the same key. */
    private String clientKeySecret;
    private static final Pattern CLIENT_KEY_SECRET = Pattern.compile("(?:[0-9a-f]{2}){32,64}");
    public boolean clientKeySecretValid() { return clientKeySecret != null && CLIENT_KEY_SECRET.matcher(clientKeySecret).matches(); }
    private int maximumReplicas = 1;
    private int publicRequestsPerSecond = 1000;
    private int privateRequestsPerSecond = 100;
    /** One client's share of its population; below the population total, or one client can still exhaust it. */
    private int publicClientRequestsPerSecond = 100;
    private int privateClientRequestsPerSecond = 30;
    /** OTP and login per client address. 30/hour is 720/day, under Identity's 1000/day notification budget. */
    private int signInClientRequestsPerHour = 30;
    /** Concurrent request uploads across all replicas. An upload holds an upstream connection (64 per replica), so the
     *  per-replica share stays at most half of them and a slow-client flood cannot take the pool from other requests. */
    private int concurrentUploads = 32;
    /** A container name on the private network: one label, so it cannot be an address or a public hostname. */
    private static final Pattern PRIVATE_SERVICE = Pattern.compile("[a-z][a-z0-9-]*");
    private static boolean origin(String value, boolean plainAllowed) {
        try {
            URI uri = URI.create(value);
            boolean secure = "https".equals(uri.getScheme());
            boolean plain = plainAllowed && "http".equals(uri.getScheme()) && uri.getHost() != null && PRIVATE_SERVICE.matcher(uri.getHost()).matches();
            return (secure || plain) && uri.getHost() != null && uri.getUserInfo() == null
                    && uri.getRawQuery() == null && uri.getFragment() == null && uri.getPath().isEmpty();
        } catch (RuntimeException ex) { return false; }
    }
    public void validate() {
        if (!origin(publicOrigin, false)) throw new IllegalStateException("Maps public origin is invalid");
        // The edge route carries the session cookie and CSRF token, so it stays on mutual TLS. The others are public
        // routes whose credentials MapsGatewayFilter strips, so plain http on the private network carries none.
        boolean valid = origin(edgeUri, false);
        for (String value : java.util.Arrays.asList(publicUri, assetsUri, postalUri)) valid &= origin(value, true);
        if (!valid) throw new IllegalStateException("Maps upstream configuration is invalid");
        if (!clientKeySecretValid()) throw new IllegalStateException("Maps client key secret is invalid");
        if (maximumReplicas < 1 || maximumReplicas > 16 || publicRequestsPerSecond < maximumReplicas
                || privateRequestsPerSecond < maximumReplicas || publicRequestsPerSecond > 10000 || privateRequestsPerSecond > 1000
                || publicClientRequestsPerSecond < maximumReplicas || publicClientRequestsPerSecond >= publicRequestsPerSecond
                || privateClientRequestsPerSecond < maximumReplicas || privateClientRequestsPerSecond >= privateRequestsPerSecond
                || signInClientRequestsPerHour < maximumReplicas || signInClientRequestsPerHour > 10000
                || concurrentUploads < maximumReplicas || concurrentUploads > 32 * maximumReplicas)
            throw new IllegalStateException("Maps admission configuration is invalid");
    }
}
