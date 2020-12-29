# ceph-adm-exporter

Small daemon for exposing `perf dump` metrics of ceph services in prometheus format.

## Usage

```
$ ./ceph-adm-exporter -h
Usage of ./ceph-adm-exporter:
  -ceph.asokglob string
        Ceph daemon admin sockets to connect. (default "/run/ceph/*.asok")
  -ceph.ignore string
        Comma separated subsystem-prefixes to ignore (default "AsyncMessenger,finisher,objectcacher,objecter-,prioritycache,recoverystate_perf,throttle")
  -version
        Display version and exit
  -web.listen-address string
        Address to listen on for web interface and telemetry. (default ":9639")
  -web.telemetry-path string
        Path under which to expose metrics. (default "/metrics")
```

## Build

We have a script to compile the application and build a docker image for easy
deployment.

```
./build.sh my-version
```

## License

```
Copyright 2020 retinadata

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
