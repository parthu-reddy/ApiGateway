# Builder stage
FROM --platform=$BUILDPLATFORM eclipse-temurin:17-jre-jammy AS builder
WORKDIR /builder
COPY ApiGateway/target/*-SNAPSHOT.jar app.jar
RUN java -Djarmode=tools -jar app.jar extract --layers --launcher --destination extracted

# Final stage
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Non-root user setup for security
RUN useradd -m spring
USER spring

# Copy layers in order of frequency of change
COPY --from=builder /builder/extracted/dependencies/ ./
COPY --from=builder /builder/extracted/spring-boot-loader/ ./
COPY --from=builder /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder /builder/extracted/application/ ./

# UTC whatever the host: log timestamps, the pgjdbc session zone, and any library that reads the
# default zone. The code never depends on it. RandomDocuments/TimezoneCorrectness_2026-09-25.
ENV TZ=UTC
# Heap 36 % of the container limit; native pools bounded. Measured 2026-10-12 (RandomDocuments/JvmMemorySizing_2026-10-12):
# non-heap is 211-490 MB per service, so 75 % let every JVM outgrow its limit and be OOM-killed.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=36.0 -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=128m -XX:+UseG1GC -Duser.timezone=UTC"
ENV MALLOC_ARENA_MAX=2

EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS org.springframework.boot.loader.launch.JarLauncher"]
