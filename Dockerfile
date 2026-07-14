# Builder stage
FROM eclipse-temurin:17-jre-jammy as builder
WORKDIR /builder
COPY ApiGateway/target/*.jar app.jar
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

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0 -XX:+UseG1GC"

EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS org.springframework.boot.loader.launch.JarLauncher"]
