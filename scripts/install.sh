#!/usr/bin/env bash
set -e

echo "[BNVD] Universal Installer"

if ! command -v git >/dev/null; then
  echo "[BNVD] Installing git"
  sudo apt update && sudo apt install -y git
fi

if ! command -v docker >/dev/null; then
  echo "[BNVD] Installing Docker"
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker $USER
fi

docker pull azurejoga/bnvd:dev

docker rm -f bnvd-app-test 2>/dev/null || true
docker run -d --name bnvd-app-test -p 4448:4448 azurejoga/bnvd:dev

echo "[BNVD] Waiting for service..."
sleep 60

if curl -fs http://localhost:4448 >/dev/null; then
  echo "[BNVD] BNVD is running successfully"
else
  echo "[BNVD] Startup failed. Logs:"
  docker logs bnvd-app-test
fi
