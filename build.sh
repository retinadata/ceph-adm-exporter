#!/bin/bash
if [ $# -eq 0 ]; then
	echo Specify version
	exit 1
fi

CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ceph-adm-exporter -ldflags "-X main.Version=$1"
docker build -t retinadata/ceph-adm-exporter:$1 .
