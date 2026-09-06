package com.fooddelivery.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.base.DescribedPredicate;
import static com.tngtech.archunit.library.Architectures.layeredArchitecture;

@AnalyzeClasses(
    packages = "com.fooddelivery",
    importOptions = {
        ImportOption.DoNotIncludeTests.class,
        ImportOption.DoNotIncludeJars.class,
        ImportOption.DoNotIncludeArchives.class
    }
)
public class ArchitectureEnforcementTest {

    private static final DescribedPredicate<JavaClass> isGeneratedOrImpl = 
        DescribedPredicate.describe("is generated or impl", 
            clazz -> clazz.getSimpleName().endsWith("Impl") 
                  || clazz.isAnnotatedWith("jakarta.annotation.Generated") 
                  || clazz.isAnnotatedWith("javax.annotation.processing.Generated"));

    private static final DescribedPredicate<JavaClass> anyClass = 
        DescribedPredicate.alwaysTrue();

    @ArchTest
    public static final ArchRule layered_architecture_is_respected = 
        layeredArchitecture()
            .consideringAllDependencies()
            .withOptionalLayers(true)
            .layer("Controller").definedBy("..controller..", "..kafka..", "..messaging..", "..beckn.bpp..", "..listener..", "..websocket..")
            .layer("Service").definedBy("..service..", "..refund..", "..scheduler..", "..security..", "..job..", "..matcher..", "..catalog..", "..settlement..", "..reconciliation..", "..event..")
            .layer("Repository").definedBy("..repository..")
            .layer("Client").definedBy("..client..")
            .layer("Config").definedBy("..config..")
            .layer("Mapper").definedBy("..mapper..")
            .layer("Filter").definedBy("..filter..")
            .layer("DTO").definedBy("..dto..", "..entity..")
            
            .whereLayer("Controller").mayOnlyBeAccessedByLayers("Config", "Service") 
            .whereLayer("Service").mayOnlyBeAccessedByLayers("Controller", "Service", "Config", "DTO", "Client")
            .whereLayer("Repository").mayOnlyBeAccessedByLayers("Service", "Controller", "Config", "Filter")
            .whereLayer("Client").mayOnlyBeAccessedByLayers("Service", "Config", "Controller")
            .ignoreDependency(isGeneratedOrImpl, anyClass);

}
