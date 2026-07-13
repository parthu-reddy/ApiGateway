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

echo "Running $IMAGE_NAME using $ENGINE..."
echo "Note: For full integration, consider running this via the deployment scripts to ensure network and env config."

$ENGINE run "$@" "$IMAGE_NAME"
