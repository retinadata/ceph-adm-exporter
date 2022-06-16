package main

import (
	"net"
	"testing"
)

func TestFixName(t *testing.T) {
	pairs := []struct {
		input  string
		output string
	}{
		{"AsyncMessenger::Worker-0", "asyncmessenger_worker_0"},
		{"AsyncMessenger::Worker-1", "asyncmessenger_worker_1"},
		{"AsyncMessenger::Worker-2", "asyncmessenger_worker_2"},
		{"bluestore", "bluestore"},
		{"finisher-objecter-finisher-0", "finisher_objecter_finisher_0"},
		{"prioritycache:data", "prioritycache_data"},
		{"recoverystate_perf", "recoverystate_perf"},
		{"throttle-msgr_dispatch_throttler-hb_back_client", "throttle_msgr_dispatch_throttler_hb_back_client"},
		{"objecter-0x5571fe57b650", "objecter_0x5571fe57b650"},
		{"throttle-objecter_ops-0x5571fe57b730", "throttle_objecter_ops_0x5571fe57b730"},
		{"ino+", "ino_opened"},
		{"ino-", "ino_closed"},
	}

	for _, p := range pairs {
		output := FixName(p.input)
		if output != p.output {
			t.Errorf("%v converted to %v must be %v", p.input, output, p.output)
		}
	}
}

func TestSocketToDaemonName(t *testing.T) {
	pairs := []struct {
		input  string
		output string
	}{
		{"/run/ceph/ceph-mgr.a.asok", "mgr.a"},
		{"/var/run/ceph/ceph-osd.123.asok", "osd.123"},
		{"current/ceph-mon.1.asok", "mon.1"},
		{"ceph-osd.93.asok", "osd.93"},
	}

	for _, p := range pairs {
		addr, err := net.ResolveUnixAddr("unix", p.input)
		if err != nil {
			t.Errorf("Unable to resolve unix addr %v", addr)
		}
		output := SocketToDaemonName(addr)
		if output != p.output {
			t.Errorf("%v converted to %v must be %v", p.input, output, p.output)
		}
	}
}

func TestDevicesRegex(t *testing.T) {
	data := []byte(`{
		"device": "/dev/sda",
		"device": "/dev/sdb"
	}`)
	matchList := devicesRegex.FindAllSubmatch(data, -1)
	ret := []string{}
	for _, match := range matchList {
		ret = append(ret, string(match[1]))
	}
	if len(ret) != 2 || ret[0] != "/dev/sda" || ret[1] != "/dev/sdb" {
		t.Errorf("ret was %v", ret)
	}
}
