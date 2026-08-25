package com.fooddelivery.apigateway.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import java.util.List;

@RestController
@lombok.extern.slf4j.Slf4j
public class FrontendLogController {

    private final com.github.benmanes.caffeine.cache.Cache<String, java.util.concurrent.atomic.AtomicInteger> requestCounts = 
        com.github.benmanes.caffeine.cache.Caffeine.newBuilder()
            .expireAfterWrite(1, java.util.concurrent.TimeUnit.MINUTES)
            .build();

    @PostMapping("/api/logs")
    public ResponseEntity<Void> logFrontendEvents(@RequestBody Map<String, Object> payload, @org.springframework.web.bind.annotation.RequestHeader(value = "X-Forwarded-For", defaultValue = "unknown") String clientIp) {
        // Simple fixed-window rate limiter per IP
        java.util.concurrent.atomic.AtomicInteger count = requestCounts.get(clientIp, k -> new java.util.concurrent.atomic.AtomicInteger(0));
        if (count.incrementAndGet() > 100) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS).build();
        }

        try {
            if (payload != null && payload.containsKey("logs")) {
                Object logsObj = payload.get("logs");
                if (logsObj instanceof List) {
                    List<?> logs = (List<?>) logsObj;
                    for (Object logEntry : logs) {
                        log.info("Frontend Log: {}", logEntry);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to parse frontend logs", e);
        }
        return ResponseEntity.ok().build();
    }
}
