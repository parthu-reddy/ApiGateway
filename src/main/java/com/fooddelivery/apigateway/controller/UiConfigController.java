package com.fooddelivery.apigateway.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/config")
@RefreshScope
public class UiConfigController {

    @Value("${olamaps.api.key:}")
    private String olaMapsApiKey;

    @GetMapping("/ui-config")
    public ResponseEntity<Map<String, String>> getUiConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("mapsApiKey", olaMapsApiKey);
        return ResponseEntity.ok(config);
    }
}
