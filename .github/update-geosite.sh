#!/bin/bash
mkdir -p /var/lib/godns
cd /var/lib/godns
wget https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
echo "$(wget -qO- https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat.sha256sum)" | sha256sum -c -
mv dlc.dat geosite.dat