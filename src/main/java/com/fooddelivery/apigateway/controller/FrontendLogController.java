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

    @PostMapping("/api/logs")
    public ResponseEntity<Void> logFrontendEvents(@RequestBody Map<String, Object> payload) {
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
