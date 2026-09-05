package com.fooddelivery.architecture;

import com.fooddelivery.common.architecture.OutboxArchitectureTest;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.junit.ArchTests;

@AnalyzeClasses(packages = "com.fooddelivery")
public class ArchitectureEnforcementTest {
    @ArchTest
    static final ArchTests sharedRules = ArchTests.in(OutboxArchitectureTest.class);
}
