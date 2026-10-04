package com.fooddelivery.apigateway.security;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;

/** A signed token must still name an owned, persisted session, including after a Dev wipe. */
public final class PersonSessionVerifier {
    private static final com.fasterxml.jackson.databind.ObjectReader READER = new ObjectMapper()
            .readerFor(JsonNode.class).with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private PersonSessionVerifier() { }

    public static boolean matches(String json, String sessionId, boolean administrator, Instant tokenExpiry) {
        if (json == null || json.length() > 16_000 || tokenExpiry == null) return false;
        try {
            JsonNode sessions = READER.readTree(json);
            if (!sessions.isArray()) return false;
            for (JsonNode session : sessions) {
                if (!session.isObject() || !session.path("sessionId").isTextual()
                        || !session.path("purpose").isTextual()
                        || !session.path("absoluteExpiresAt").isTextual()) return false;
                if (sessionId.equals(session.path("sessionId").asText())) {
                    String purpose = administrator ? "ADMIN" : "LOGIN";
                    return purpose.equals(session.path("purpose").asText())
                            && !tokenExpiry.isAfter(Instant.parse(session.path("absoluteExpiresAt").asText()));
                }
            }
        } catch (Exception ignored) { /* Invalid cache state cannot grant access. */ }
        return false;
    }
}
