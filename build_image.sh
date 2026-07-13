#!/bin/bash
set -e

ENGINE="docker"
if [ "$1" == "--apple" ] || [ "$1" == "--container" ]; then
    ENGINE="container"
    shift
elif [ "$1" == "--docker" ]; then
    ENGINE="docker"
    shift
fi

SERVICE_DIR=$(basename "$(pwd)")
# Convert directory name to lowercase for image tagging
IMAGE_NAME=$(echo "$SERVICE_DIR" | tr '[:upper:]' '[:lower:]'):latest

echo "Building $IMAGE_NAME using $ENGINE..."

# Change to the parent directory (project root) so that COPY commands in Dockerfile work correctly
cd ..

$ENGINE build "$@" -f "$SERVICE_DIR/Dockerfile" -t "$IMAGE_NAME" .
echo "Build complete."
