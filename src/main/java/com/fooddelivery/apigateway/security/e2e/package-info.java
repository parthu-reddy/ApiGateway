/**
 * Runtime authorization guards for the isolated {@code e2e} Spring profile.
 *
 * <p>The classes here are packaged with the gateway rather than test sources because they enforce
 * access on deployed requests. They are instantiated only when {@code e2e} is explicitly active;
 * {@code dev} and production profiles expose no E2E OTP admission path.</p>
 */
package com.fooddelivery.apigateway.security.e2e;
