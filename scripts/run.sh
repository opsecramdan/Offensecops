#!/bin/bash
# OffenSecOps - Quick Setup Script
# Usage: cd /path/to/offensecops && bash scripts/run.sh

set -e

echo "=========================================="
echo " OffenSecOps Setup Script"
echo "=========================================="

# Check .env exists
if [ ! -f .env ]; then
  echo "[!] .env not found. Copying from .env.example..."
  cp .env.example .env
  echo "[!] Please edit .env with your passwords before continuing"
  echo "    nano .env"
  exit 1
fi

echo "[1/3] Building Docker images..."
docker compose build

echo "[2/3] Starting services..."
docker compose up -d

echo "[3/3] Waiting for services to be ready..."
sleep 10

echo "=========================================="
echo " OffenSecOps is running!"
echo " Access: http://$(hostname -I | awk '{print $1}')"
echo "=========================================="
