package com.fooddelivery.apigateway.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class IndexController {

    @Value("classpath:/static/index.html")
    private Resource indexHtml;

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public Mono<Resource> index() {
        return Mono.just(indexHtml);
    }
}
