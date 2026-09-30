package com.fooddelivery.apigateway.security.e2e;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Runtime-only fixed-length digest comparison for the e2e runner credential.
 * The e2e profile creates this helper; ordinary dev and production profiles do not.
 */
final class E2eRunnerSecretVerifier {

    private final byte[] expectedDigest;

    E2eRunnerSecretVerifier(String runnerSecret) {
        if (runnerSecret == null || runnerSecret.isBlank()) {
            throw new IllegalStateException(
                    "e2e.runner.secret must be configured when the e2e profile is active");
        }
        expectedDigest = digest(runnerSecret);
    }

    boolean matches(List<String> suppliedSecrets) {
        return suppliedSecrets != null
                && suppliedSecrets.size() == 1
                && suppliedSecrets.get(0) != null
                && MessageDigest.isEqual(expectedDigest, digest(suppliedSecrets.get(0)));
    }

    private static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required for E2E runner authentication", exception);
        }
    }
}
