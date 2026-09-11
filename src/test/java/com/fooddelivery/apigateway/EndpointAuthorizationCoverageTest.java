package com.fooddelivery.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.File;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every endpoint the gateway serves itself must be a reviewed decision.
 *
 * <p><b>Deliberately self-contained, unlike the other fifteen modules.</b> Those use
 * {@code EndpointAuthorizationCoverage} from common-library's test-jar. This module cannot:
 *
 * <ul>
 *   <li>common-library on the compile classpath pulls spring-boot-starter-web, and Spring Cloud
 *       Gateway refuses to start with Spring MVC present -- the constraint the identity-signing
 *       module exists to work around;</li>
 *   <li>and as a test-jar it is no better. Tried on 2026-08-28: {@code ApiGatewayApplication}
 *       component-scans {@code com.fooddelivery.common}, so the scan picked up common-library's TEST
 *       classes, which {@code @Import} main classes the exclusions had removed. The context failed
 *       with {@code ClassNotFoundException: CommonSecurityConfig}.</li>
 * </ul>
 *
 * <p><b>And the check itself has to differ.</b> ApiGateway has no Spring Security at all: no security
 * dependency, no {@code @EnableReactiveMethodSecurity}. A {@code @PreAuthorize} here would be inert.
 * Authorization is done by {@code GlobalJwtAuthFilter}, a {@code GlobalFilter}. So rather than look
 * for annotations that could never be enforced, this pins the SET of endpoints the gateway serves
 * itself: a new one fails until someone records which filter rule gates it.
 */
class EndpointAuthorizationCoverageTest {

    private static final String BASE_PACKAGE = "com.fooddelivery.apigateway";

    /**
     * Every endpoint the gateway serves directly, each with the {@code GlobalJwtAuthFilter} rule that
     * gates it. Verified against its public-path list on 2026-09-10.
     *
     * <ul>
     *   <li>{@code IndexController#index} -- "/" is explicitly public, so the SPA shell loads before
     *       sign-in.</li>
     *   <li>{@code FrontendLogController#logFrontendEvents} -- /api/logs is not public either, so it
     *       is authenticated. Validator check I-36b asserts exactly this.</li>
     * </ul>
     */
    private static final Set<String> REVIEWED_ENDPOINTS = Set.of(
            "IndexController#index",
            "FrontendLogController#logFrontendEvents");

    private static final Set<String> MAPPINGS = Set.of(
            "org.springframework.web.bind.annotation.GetMapping",
            "org.springframework.web.bind.annotation.PostMapping",
            "org.springframework.web.bind.annotation.PutMapping",
            "org.springframework.web.bind.annotation.DeleteMapping",
            "org.springframework.web.bind.annotation.PatchMapping",
            "org.springframework.web.bind.annotation.RequestMapping");

    private static Set<String> discoverEndpoints() throws Exception {
        Set<String> found = new TreeSet<>();
        for (Class<?> type : classesIn(BASE_PACKAGE)) {
            for (Method method : type.getDeclaredMethods()) {
                for (Annotation a : method.getAnnotations()) {
                    if (MAPPINGS.contains(a.annotationType().getName())) {
                        found.add(type.getSimpleName() + "#" + method.getName());
                        break;
                    }
                }
            }
        }
        return found;
    }

    private static List<Class<?>> classesIn(String pkg) throws Exception {
        List<Class<?>> classes = new ArrayList<>();
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        Enumeration<URL> resources = cl.getResources(pkg.replace('.', '/'));
        while (resources.hasMoreElements()) {
            File dir = new File(resources.nextElement().toURI());
            collect(dir, pkg, classes, cl);
        }
        return classes;
    }

    private static void collect(File dir, String pkg, List<Class<?>> out, ClassLoader cl) throws Exception {
        File[] entries = dir.listFiles();
        if (entries == null) {
            return;
        }
        for (File f : entries) {
            if (f.isDirectory()) {
                collect(f, pkg + "." + f.getName(), out, cl);
            } else if (f.getName().endsWith(".class") && !f.getName().contains("$")) {
                try {
                    out.add(Class.forName(pkg + "." + f.getName().replace(".class", ""), false, cl));
                } catch (Throwable ignored) {
                    // a class we cannot load is not an endpoint we can assert about
                }
            }
        }
    }

    /**
     * A scan finding nothing would report "no unreviewed endpoints" and pass while guarding nothing.
     */
    @Test
    void theScanActuallyFindsEndpoints() throws Exception {
        assertThat(discoverEndpoints())
                .describedAs("endpoints discovered under " + BASE_PACKAGE)
                .isNotEmpty();
    }

    @Test
    void everyGatewayServedEndpointHasBeenReviewed() throws Exception {
        Set<String> found = new TreeSet<>(discoverEndpoints());
        found.removeAll(REVIEWED_ENDPOINTS);
        assertThat(found)
                .describedAs("Gateway endpoints with no entry in REVIEWED_ENDPOINTS. Add one naming "
                        + "the GlobalJwtAuthFilter rule that gates it. A @PreAuthorize would be inert "
                        + "here: this module has no method security.")
                .isEmpty();
    }

    /** An entry that outlives its endpoint silently weakens the check. */
    @Test
    void theReviewedListHasNoStaleEntries() throws Exception {
        Set<String> stale = new TreeSet<>(REVIEWED_ENDPOINTS);
        stale.removeAll(discoverEndpoints());
        assertThat(stale).describedAs("reviewed entries matching no endpoint").isEmpty();
    }
}
