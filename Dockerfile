FROM scratch

ADD ceph-adm-exporter /

ENTRYPOINT ["/ceph-adm-exporter"]
