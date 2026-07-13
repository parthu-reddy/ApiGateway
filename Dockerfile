FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Non-root user setup for security
RUN useradd -m spring
USER spring

# Copy pre-compiled JAR from the target directory
COPY ApiGateway/target/*.jar app.jar

# Copy certs directly into image to avoid volume mounting issues on macOS
USER root
RUN mkdir -p /certs && chown spring:spring /certs
USER spring
COPY --chown=spring:spring Deployment/certs/public.pem /certs/public.pem

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0 -XX:+UseG1GC"

EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
