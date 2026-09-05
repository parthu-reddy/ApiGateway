package com.fooddelivery.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication(
    scanBasePackages = {"com.fooddelivery.apigateway", "com.fooddelivery.common"}
)
@org.springframework.context.annotation.ComponentScan(
    basePackages = {"com.fooddelivery", "com.fooddelivery.common"},
    excludeFilters = @org.springframework.context.annotation.ComponentScan.Filter(
        type = org.springframework.context.annotation.FilterType.REGEX,
        pattern = "com\\.fooddelivery\\.common\\.security\\.CommonSecurityConfig"
    )
)
@EnableDiscoveryClient
public class ApiGatewayApplication {
	public static void main(String[] args) {
		SpringApplication.run(ApiGatewayApplication.class, args);
	}
}
