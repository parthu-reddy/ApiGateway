package com.fooddelivery.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RbacRulesTest extends GatewayApplicationFixture {

    @Autowired
    private Environment env;

    @Test
    void customerRoleRules() {
        List<String> customerRules = getListProperty("rbac.rules.customer");
        assertThat(customerRules).doesNotContain("/api/v1/payments");
        assertThat(customerRules).contains("/api/v1/money/customer");
    }

    @Test
    void restaurantRoleRules() {
        List<String> restaurantRules = getListProperty("rbac.rules.restaurant");
        assertThat(restaurantRules).doesNotContain("/api/v1/wallets", "/api/v1/money/advertiser", "/api/v1/advertisers");
        assertThat(restaurantRules).contains("/api/v1/money/restaurant");
    }

    /** The business wallet and the ad account belong to the organisation, so the BUSINESS role reaches them (W1, A1). */
    @Test
    void businessRoleRules() {
        assertThat(getListProperty("rbac.rules.business")).containsExactlyInAnyOrder("/api/v1/money/business", "/api/v1/advertisers");
    }

    @Test
    void deliveryRoleRules() {
        List<String> deliveryRules = getListProperty("rbac.rules.delivery");
        assertThat(deliveryRules).contains("/api/v1/money/driver");
    }

    private List<String> getListProperty(String key) {
        return org.springframework.boot.context.properties.bind.Binder.get(env)
                .bind(key, org.springframework.boot.context.properties.bind.Bindable.listOf(String.class))
                .orElse(List.of());
    }
}
