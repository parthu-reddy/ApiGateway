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
        if (json == null || json.length() > 16_000 || sessionId == null || tokenExpiry == null) return false;
        try {
            JsonNode sessions = READER.readTree(json);
            if (!sessions.isArray()) return false;
            boolean matched = false;
            java.util.Set<String> ids = new java.util.HashSet<>();
            for (JsonNode session : sessions) {
                if (!session.isObject() || !session.path("sessionId").isTextual()
                        || !session.path("purpose").isTextual()
                        || !session.path("absoluteExpiresAt").isTextual()) return false;
                String id = session.path("sessionId").asText();
                String purpose = session.path("purpose").asText();
                Instant absoluteExpiry = Instant.parse(session.path("absoluteExpiresAt").asText());
                if (id.isBlank() || !ids.add(id) || !("LOGIN".equals(purpose) || "ADMIN".equals(purpose))) return false;
                if (sessionId.equals(id)) {
                    matched = (administrator ? "ADMIN" : "LOGIN").equals(purpose)
                            && !tokenExpiry.isAfter(absoluteExpiry);
                }
            }
            return matched;
        } catch (Exception ignored) { /* Invalid cache state cannot grant access. */ }
        return false;
    }
}
