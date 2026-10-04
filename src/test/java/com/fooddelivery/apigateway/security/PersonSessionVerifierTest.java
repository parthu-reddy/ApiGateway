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
}
