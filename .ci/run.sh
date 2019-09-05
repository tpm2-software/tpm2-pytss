#!/bin/bash
set -e

echo "Building style check image..."
docker build -t tpm2software/tpm2-tss-python-black \
  -f .ci/Dockerfile.tpm2-tss-python-black .
echo "Style check image built"

echo "Building docker image..."
docker build -t tpm2software/tpm2-tss-python \
  -f .ci/Dockerfile.tpm2-tss-python .
echo "Docker image built"

echo "Running build..."
docker run --rm \
  -u $(id -u):$(id -g) \
  -v "${PWD}:/workspace/tpm2-pytss" \
  --env-file .ci/docker.env \
  tpm2software/tpm2-tss-python \
  /bin/bash -c 'python3 setup.py sdist && python3 setup.py bdist'
echo "Build success"

echo "Checking style..."
docker run --rm \
  -u $(id -u):$(id -g) \
  -v "${PWD}:/workspace/tpm2-pytss" \
  tpm2software/tpm2-tss-python-black \
  --check .
echo "Style check passed"

echo "Running tests..."
docker run --rm \
  -u $(id -u):$(id -g) \
  -v "${PWD}:/workspace/tpm2-pytss" \
  --env-file .ci/docker.env \
  tpm2software/tpm2-tss-python \
  /bin/bash -c '/workspace/tpm2-pytss/.ci/docker.run'
echo "Tests passed"

echo "Creating docs..."
rm -rf public
docker run --rm \
  -u $(id -u):$(id -g) \
  -v "${PWD}:/workspace/tpm2-pytss" \
  --env-file .ci/docker.env \
  tpm2software/tpm2-tss-python \
  /bin/bash -c "./scripts/docs.sh && mv pages public"
echo "Documentation generated successfully"
