#!/bin/bash

# 使用第一个参数作为目标目录，默认值为当前目录
TARGET_DIR="${1:-$(pwd)}"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR" || exit 1

wget https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
echo "$(wget -qO- https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat.sha256sum)" | sha256sum -c -
mv dlc.dat geosite.dat
