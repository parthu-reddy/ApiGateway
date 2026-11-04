package com.fooddelivery.apigateway.security;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PersonSessionVerifierTest {
    private final Instant expiry = Instant.parse("2026-10-04T12:00:00Z");
    private String session(String purpose, String absolute) {
        return "[{\"sessionId\":\"owned\",\"purpose\":\"" + purpose
                + "\",\"absoluteExpiresAt\":\"" + absolute + "\"}]";
    }
    @Test void everydayAndAdministratorSessionsRequireTheirOwnPurpose() {
        String ordinary = session("LOGIN", "2026-11-01T12:00:00Z");
        String administrator = session("ADMIN", "2026-10-04T12:00:00Z");
        assertTrue(PersonSessionVerifier.matches(ordinary, "owned", false, expiry));
        assertTrue(PersonSessionVerifier.matches(administrator, "owned", true, expiry));
        assertFalse(PersonSessionVerifier.matches(ordinary, "owned", true, expiry));
        assertFalse(PersonSessionVerifier.matches(administrator, "owned", false, expiry));
    }
    @Test void aTokenCannotExceedTheSessionsAbsoluteLifetime() {
        assertFalse(PersonSessionVerifier.matches(session("ADMIN", "2026-10-04T11:59:59Z"), "owned", true, expiry));
    }
    @Test void malformedOrAbsentSessionStateFailsClosed() {
        for (String value : new String[]{null, "null", "{}", "[]", "[null]", "[] []", "[{\"sessionId\":\"owned\"}]"})
            assertFalse(PersonSessionVerifier.matches(value, "owned", false, expiry));
        assertFalse(PersonSessionVerifier.matches(session("LOGIN", "invalid"), "owned", false, expiry));
    }
    @Test void aValidMatchCannotHideInvalidOrDuplicateRowsLaterInTheRegistry() {
        String valid = session("LOGIN", "2026-11-01T12:00:00Z");
        String prefix = valid.substring(0, valid.length() - 1) + ",";
        for (String row : new String[]{"null", "{}",
                "{\"sessionId\":\"other\",\"purpose\":\"LOGIN\",\"absoluteExpiresAt\":\"invalid\"}",
                "{\"sessionId\":\"other\",\"purpose\":\"UNKNOWN\",\"absoluteExpiresAt\":\"2026-11-01T12:00:00Z\"}",
                valid.substring(1, valid.length() - 1)}) {
            assertFalse(PersonSessionVerifier.matches(prefix + row + "]", "owned", false, expiry), row);
        }
        String other = valid.substring(1, valid.length() - 1).replace("owned", "other");
        assertTrue(PersonSessionVerifier.matches(prefix + other + "]", "owned", false, expiry));
    }

    @Test void duplicateJsonPropertiesCannotSelectTheWinningAuthority() {
        String valid = session("LOGIN", "2026-11-01T12:00:00Z");
        for (String malformed : new String[]{
                valid.replace("\"sessionId\":\"owned\"", "\"sessionId\":\"foreign\",\"sessionId\":\"owned\""),
                valid.replace("\"purpose\":\"LOGIN\"", "\"purpose\":\"ADMIN\",\"purpose\":\"LOGIN\""),
                valid.replace("\"purpose\":\"LOGIN\"", "\"purpose\":\"LOGIN\",\"purpose\":\"LOGIN\""),
                valid.replace("\"absoluteExpiresAt\":", "\"absoluteExpiresAt\":\"2026-10-01T00:00:00Z\",\"absoluteExpiresAt\":"),
                valid.replace("}", ",\"metadata\":{\"a\":1,\"a\":2}}")}) {
            assertFalse(PersonSessionVerifier.matches(malformed, "owned", false, expiry));
        }
    }

    @Test void sizeLimitCountsUtf8BytesAndIncludesIgnoredProperties() {
        String valid = session("LOGIN", "2026-11-01T12:00:00Z");
        assertFalse(PersonSessionVerifier.matches(valid.replace("}", ",\"deviceInfo\":\"" + "é".repeat(8100) + "\"}"), "owned", false, expiry));
        assertTrue(PersonSessionVerifier.matches(valid.replace("}", ",\"deviceInfo\":\"" + "x".repeat(15000) + "\"}"), "owned", false, expiry));
    }

    @Test void scalarCoercionCannotCreateAStoredSessionIdentity() {
        String valid = session("LOGIN", "2026-11-01T12:00:00Z");
        assertFalse(PersonSessionVerifier.matches(valid.replace("\"owned\"", "123"), "123", false, expiry));
        assertFalse(PersonSessionVerifier.matches(valid.replace("\"LOGIN\"", "0"), "owned", false, expiry));
        assertFalse(PersonSessionVerifier.matches(valid, null, false, expiry));
        assertFalse(PersonSessionVerifier.matches(valid, "owned", false, null));
    }

    @Test void byteBudgetHasAnInclusiveBoundary() {
        String valid = session("LOGIN", "2026-11-01T12:00:00Z");
        String exact = valid + " ".repeat(16_000 - valid.length());
        assertTrue(PersonSessionVerifier.matches(exact, "owned", false, expiry));
        assertFalse(PersonSessionVerifier.matches(exact + " ", "owned", false, expiry));
    }
}
