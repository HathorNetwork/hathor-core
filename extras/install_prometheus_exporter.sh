#!/bin/bash

sudo useradd --no-create-home --shell /bin/false node_exporter

curl -LO https://github.com/prometheus/node_exporter/releases/download/v0.16.0/node_exporter-0.16.0.linux-amd64.tar.gz

tar xvf node_exporter-0.16.0.linux-amd64.tar.gz

sudo cp node_exporter-0.16.0.linux-amd64/node_exporter /usr/local/bin
sudo chown node_exporter:node_exporter /usr/local/bin/node_exporter

rm -rf node_exporter-0.16.0.linux-amd64.tar.gz node_exporter-0.16.0.linux-amd64/

sudo cp node_exporter.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl status node_exporter

echo "Remember to allow access to metrics.testnet.hathor.network at port 9100"
