# Builder stage
FROM --platform=$BUILDPLATFORM eclipse-temurin:21-jre-jammy AS builder
WORKDIR /builder
COPY ApiGateway/target/*-SNAPSHOT.jar app.jar
# Clamp file times so identical content gives identical layers. extract stamps everything with the build time, so
# the 114 MB dependencies layer had a new digest on every build: every CI push re-uploaded it to OCIR and every
# deploy re-pulled it. RandomDocuments/ReleaseSpeed_2026-10-15 Phase 2.
RUN java -Djarmode=tools -jar app.jar extract --layers --launcher --destination extracted \
    && find extracted -exec touch -h -d @0 {} +

# Final stage
FROM eclipse-temurin:21-jre-jammy
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
# C2 compile thresholds x10 (Tier4*): code reaches C2 later, so a start spends less CPU compiling. Measured 2026-10-19
# (RandomDocuments/JvmStartupCpu_2026-10-19): catalog-service to context refresh 34.6 -> 21.8 cpu-s, steady-state
# throughput 99 % of default, full speed after ~15 s of load. The 22 JVMs start together on 4 cores in every deploy.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=36.0 -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=128m -XX:+UseG1GC -Duser.timezone=UTC -XX:Tier4InvocationThreshold=50000 -XX:Tier4MinInvocationThreshold=6000 -XX:Tier4CompileThreshold=150000 -XX:Tier4BackEdgeThreshold=400000"
ENV MALLOC_ARENA_MAX=2

EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS org.springframework.boot.loader.launch.JarLauncher"]
