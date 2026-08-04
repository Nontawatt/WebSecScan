#!/usr/bin/env bash
# build + run WebSecScan ใน Docker (บน WSL/Linux)
# ใช้:  ./docker-run.sh            -> build แล้วรัน เปิดที่ http://127.0.0.1:8091
#       PORT=9000 ./docker-run.sh  -> เปลี่ยนพอร์ต host
set -e
cd "$(dirname "$0")"
IMG="websecscan"
PORT="${PORT:-8091}"

# ใช้ docker ได้เลยถ้ามีสิทธิ์ ไม่งั้น fallback เป็น sudo docker
DOCKER="docker"
if ! docker info >/dev/null 2>&1; then
  echo "[i] ไม่มีสิทธิ์เข้าถึง docker โดยตรง — ใช้ sudo docker (จะถามรหัสผ่าน)"
  DOCKER="sudo docker"
fi

echo "[1/2] build image: $IMG"
$DOCKER build -t "$IMG" .

mkdir -p data
echo "[2/2] run -> http://127.0.0.1:${PORT}   (ผลเก็บใน ./data, ปิดด้วย Ctrl+C)"
exec $DOCKER run --rm -it \
  -p 127.0.0.1:${PORT}:8091 \
  -v "$PWD/data:/app/data" \
  --name websecscan \
  "$IMG"
