package com.fooddelivery.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

class ApiGatewayApplicationStartupTest extends GatewayApplicationFixture {
@org.springframework.beans.factory.annotation.Autowired org.springframework.context.ApplicationContext context;
@Test
    void contextLoads() {
        org.junit.jupiter.api.Assertions.assertTrue(context.containsBean("globalJwtAuthFilter"));
        org.junit.jupiter.api.Assertions.assertFalse(context.containsBean("eurekaClient"));
    }
}
