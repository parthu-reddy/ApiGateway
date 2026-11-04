package com.fooddelivery.apigateway.config;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;

@lombok.Data
@ConfigurationProperties("gateway.maps")
public class MapsGatewayProperties {
    private boolean enabled;
    private String edgeUri, publicUri, assetsUri, postalUri, routingUri;
    private int maximumReplicas = 1;
    private int publicRequestsPerSecond = 1000;
    private int privateRequestsPerSecond = 100;
    public void validate() {
        for (String value : java.util.Arrays.asList(edgeUri, publicUri, assetsUri, postalUri, routingUri)) {
            try {
                URI uri = URI.create(value);
                if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                        || uri.getRawQuery() != null || uri.getFragment() != null || !uri.getPath().isEmpty())
                    throw new IllegalArgumentException();
            } catch (RuntimeException ex) { throw new IllegalStateException("Maps upstream configuration is invalid"); }
        }
        if (maximumReplicas < 1 || maximumReplicas > 16 || publicRequestsPerSecond < maximumReplicas
                || privateRequestsPerSecond < maximumReplicas || publicRequestsPerSecond > 10000 || privateRequestsPerSecond > 1000)
            throw new IllegalStateException("Maps admission configuration is invalid");
    }
}
