package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace          = "ceph"
	daemonLabel        = "ceph_daemon"
	daemonVersionLabel = "ceph_version"
	deviceLabel        = "device"
)

var (
	// Version specifies the binary version
	Version            = "undefined"
	dumpCommand        = []byte("{\"prefix\":\"perf dump\"}\x00")
	schemaCommand      = []byte("{\"prefix\":\"perf schema\"}\x00")
	versionCommand     = []byte("{\"prefix\":\"version\"}\x00")
	listDevicesCommand = []byte("{\"prefix\":\"list_devices\"}\x00")
	ignoredSubSystems  = []string{}
	labels             = []string{daemonLabel}
	metricNameRegex    = regexp.MustCompile("[^a-z0-9]+")
	devicesRegex       = regexp.MustCompile(`"device" *: *"([A-Za-z0-9/]+)"`)
	plusEndRegex       = regexp.MustCompile("\\+$")
	minusEndRegex      = regexp.MustCompile("\\-$")
)

// CephDesc defines a metric type read from perf schema
type CephDesc struct {
	CephType    int    `json:"type"`
	MetricType  string `json:"metric_type"`
	ValueType   string `json:"value_type"`
	Description string `json:"description"`
	Nick        string `json:"nick"`
	Priority    int    `json:"priority"`
	Units       string `json:"units"`
}

// CephVersion defines the version object read from the daemons
type CephVersion struct {
	Version     string `json:"version"`
	Release     string `json:"release"`
	ReleaseType string `json:"release_type"`
}

type cephPerfSchema map[string]map[string]CephDesc
type cephPerfDump map[string]map[string]interface{}

type cephAdmDesc struct {
	promDesc *prometheus.Desc
	promType prometheus.ValueType
}
type cephAdmDescriptions map[string]*cephAdmDesc

// SocketToDaemonName converts a socket filename like ceph-osd.1.asok to osd.1
func SocketToDaemonName(adminSocket *net.UnixAddr) string {
	fileName := filepath.Base(adminSocket.Name)
	fileName = strings.Replace(fileName, "ceph-", "", 1)
	fileName = strings.Replace(fileName, ".asok", "", 1)
	return fileName
}

// FixName removes special characters in the metric name to comply with
// Prometheus naming rules
func FixName(name string) string {
	name = strings.ToLower(name)
	// mds have some metrics like ino+ and ino-
	// meanining inodes opened and closed
	// expand them to avoid name collision after regex
	name = plusEndRegex.ReplaceAllString(name, "_opened")
	name = minusEndRegex.ReplaceAllString(name, "_closed")
	return metricNameRegex.ReplaceAllString(name, "_")
}

func readFromSocket(adminSocket *net.UnixAddr, command []byte) (*[]byte, error) {
	conn, err := net.DialUnix("unix", nil, adminSocket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// send command
	_, err = conn.Write(command)
	if err != nil {
		return nil, err
	}

	// socket will return data size in 4 bytes, read that first
	lenB := make([]byte, 4)
	four, err := conn.Read(lenB)
	if err != nil {
		return nil, err
	}
	if four < 4 {
		return nil, errors.New("Unable to read from admin socket")
	}

	len := binary.BigEndian.Uint32(lenB)
	dataB := make([]byte, int(len))
	dataSize, err := conn.Read(dataB)
	if err != nil {
		return nil, err
	}
	if dataSize < int(len) {
		return nil, errors.New("Read incomplete data from admin socket")
	}
	return &dataB, nil
}

func readVersion(adminSocket *net.UnixAddr) (CephVersion, error) {
	cv := CephVersion{}
	data, err := readFromSocket(adminSocket, versionCommand)
	if err != nil {
		return cv, err
	}

	err = json.Unmarshal(*data, &cv)
	if err != nil {
		return cv, err
	}
	return cv, nil
}

func readDevices14(adminSocket *net.UnixAddr) ([]string, error) {
	data, err := readFromSocket(adminSocket, listDevicesCommand)
	if err != nil {
		return nil, err
	}

	matchList := devicesRegex.FindAllSubmatch(*data, -1)
	ret := []string{}
	for _, match := range matchList {
		ret = append(ret, string(match[1]))
	}

	return ret, nil
}

func readDump(adminSocket *net.UnixAddr) (cephPerfDump, error) {
	data, err := readFromSocket(adminSocket, dumpCommand)
	if err != nil {
		return nil, err
	}

	dump := make(cephPerfDump)
	err = json.Unmarshal(*data, &dump)
	if err != nil {
		return nil, err
	}
	return dump, nil
}

func readSchema(adminSocket *net.UnixAddr) (cephPerfSchema, error) {
	data, err := readFromSocket(adminSocket, schemaCommand)
	if err != nil {
		return nil, err
	}

	schema := make(cephPerfSchema)
	err = json.Unmarshal(*data, &schema)
	if err != nil {
		return nil, err
	}
	return schema, nil
}

func schemaToDescriptions(schema cephPerfSchema, descriptions *cephAdmDescriptions) {
	for subSystem, descs := range schema {
		ignore := false
		for _, ignoredSubSystem := range ignoredSubSystems {
			if strings.HasPrefix(subSystem, ignoredSubSystem) {
				ignore = true
				continue
			}
		}
		if ignore {
			continue
		}

		for name, cephDesc := range descs {
			fqName := prometheus.BuildFQName(namespace, FixName(subSystem), FixName(name))
			if _, in := (*descriptions)[fqName]; !in {
				var promType prometheus.ValueType
				if cephDesc.MetricType == "gauge" {
					promType = prometheus.GaugeValue
				} else if cephDesc.MetricType == "counter" {
					promType = prometheus.CounterValue
				} else {
					promType = prometheus.UntypedValue
				}

				if cephDesc.ValueType == "integer" || cephDesc.ValueType == "real" {
					(*descriptions)[fqName] = &cephAdmDesc{
						promDesc: prometheus.NewDesc(fqName, cephDesc.Description, labels, nil),
						promType: promType,
					}
				} else if cephDesc.ValueType == "real-integer-pair" {
					(*descriptions)[fqName+"_avgcount"] = &cephAdmDesc{
						promDesc: prometheus.NewDesc(fqName+"_avgcount", cephDesc.Description+" avgcount", labels, nil),
						promType: prometheus.GaugeValue,
					}
					(*descriptions)[fqName+"_avgtime"] = &cephAdmDesc{
						promDesc: prometheus.NewDesc(fqName+"_avgtime", cephDesc.Description+" avgtime", labels, nil),
						promType: prometheus.GaugeValue,
					}
					(*descriptions)[fqName+"_sum"] = &cephAdmDesc{
						promDesc: prometheus.NewDesc(fqName+"_sum", cephDesc.Description+" sum", labels, nil),
						promType: prometheus.CounterValue,
					}
				} else if cephDesc.ValueType == "integer-integer-pair" {
					(*descriptions)[fqName+"_avgcount"] = &cephAdmDesc{
						promDesc: prometheus.NewDesc(fqName+"_avgcount", cephDesc.Description+" avgcount", labels, nil),
						promType: prometheus.GaugeValue,
					}
					(*descriptions)[fqName+"_sum"] = &cephAdmDesc{
						promDesc: prometheus.NewDesc(fqName+"_sum", cephDesc.Description+" sum", labels, nil),
						promType: prometheus.CounterValue,
					}
				}
			}
		}
	}
}

// CephADMCollector implements prometheus.Collector type
type CephADMCollector struct {
	up           *prometheus.GaugeVec
	version      *prometheus.Desc
	device       *prometheus.Desc
	descriptions cephAdmDescriptions
	asokGlob     string
}

// NewCephADMCollector returns an initialized CephADMCollector
func NewCephADMCollector(asokGlob string) *CephADMCollector {
	ret := &CephADMCollector{
		up: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "Was the last scrape of this admin socket successful",
		}, labels),
		version:  prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "version"), "Ceph daemon version", append(labels, daemonVersionLabel), nil),
		device:   prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "device"), "Ceph OSD devices", append(labels, deviceLabel), nil),
		asokGlob: asokGlob,
	}
	go ret.updateDecriptions()
	return ret
}

func (t *CephADMCollector) findSockets() ([]*net.UnixAddr, error) {
	adminSockets, err := filepath.Glob(t.asokGlob)
	if err != nil {
		return nil, err
	}
	if len(adminSockets) == 0 {
		return make([]*net.UnixAddr, 0), nil
	}
	var socketAddrs []*net.UnixAddr

	for _, adminSocket := range adminSockets {
		adminSocketAddr, err := net.ResolveUnixAddr("unix", adminSocket)
		if err != nil {
			log.Warnf("Cannot resolve matched file %v as a unix socket", adminSocket)
			continue
		}
		socketAddrs = append(socketAddrs, adminSocketAddr)
	}
	return socketAddrs, nil
}

func (t *CephADMCollector) updateDecriptions() {
	descriptions := make(cephAdmDescriptions)
	socketAddrs, err := t.findSockets()
	if err != nil {
		panic(err)
	}
	log.Infof("Found %v socket(s). Reading schemas", len(socketAddrs))

	for _, socketAddr := range socketAddrs {
		schema, err := readSchema(socketAddr)
		if err != nil {
			log.Warnf("Unable to read perf schema from %v %v", socketAddr.Name, err)
			continue
		}
		schemaToDescriptions(schema, &descriptions)
	}
	t.descriptions = descriptions
}

// Describe implements prometheus.Collector.Describe
func (t *CephADMCollector) Describe(c chan<- *prometheus.Desc) {
	t.up.Describe(c)
	c <- t.version
	c <- t.device
	for _, desc := range t.descriptions {
		c <- desc.promDesc
	}
}

// Collect implements prometheus.Collector.Collect
func (t *CephADMCollector) Collect(c chan<- prometheus.Metric) {
	if t.descriptions == nil {
		t.updateDecriptions()
	}
	if socketAddrs, err := t.findSockets(); err != nil {
		log.Warnf("Unable to find admin sockets %v", err)
	} else {
		for _, socketAddr := range socketAddrs {
			daemonName := SocketToDaemonName(socketAddr)
			daemonUp := t.up.WithLabelValues(daemonName)
			daemonUp.Set(0)
			if daemonVersion, err := readVersion(socketAddr); err == nil {
				c <- prometheus.MustNewConstMetric(t.version, prometheus.UntypedValue, 1, daemonName, daemonVersion.Version)
				if strings.HasPrefix(daemonName, "osd") && strings.HasPrefix(daemonVersion.Version, "14") {
					if devices, err := readDevices14(socketAddr); err == nil {
						for _, device := range devices {
							c <- prometheus.MustNewConstMetric(t.device, prometheus.UntypedValue, 1, daemonName, device)
						}
					} else {
						log.Warnf("Unable to read devices from %v : %v", socketAddr, err)
					}
				}
			} else {
				log.Warnf("Unable to read version from %v : %v", socketAddr, err)
			}
			dump, err := readDump(socketAddr)
			if err != nil {
				log.Warnf("Unable to read perf dump from %v : %v", socketAddr, err)
				c <- daemonUp
				continue
			}
			t.dumpToMetrics(daemonName, dump, c)
			daemonUp.Set(1)
			c <- daemonUp
		}
	}
}

func (t *CephADMCollector) dumpToMetrics(daemonName string, dump cephPerfDump, c chan<- prometheus.Metric) {
	for subSystem, metrics := range dump {
		for name, metric := range metrics {
			fqName := prometheus.BuildFQName(namespace, FixName(subSystem), FixName(name))
			switch value := metric.(type) {
			case float64:
				t.sendMetric(daemonName, fqName, value, c)
			case map[string]interface{}:
				for detailName, detailValue := range value {
					if dv, ok := detailValue.(float64); ok {
						t.sendMetric(daemonName, fqName+"_"+FixName(detailName), dv, c)
					}
				}
			default:

			}
		}
	}
}

func (t *CephADMCollector) sendMetric(daemonName string, name string, value float64, c chan<- prometheus.Metric) {
	if desc, in := t.descriptions[name]; in {
		c <- prometheus.MustNewConstMetric(desc.promDesc, desc.promType, value, daemonName)
	}
}

func main() {
	var (
		version          = flag.Bool("version", false, "Display version and exit")
		listenAddress    = flag.String("web.listen-address", ":9639", "Address to listen on for web interface and telemetry.")
		metricsPath      = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		asokGlob         = flag.String("ceph.asokglob", "/run/ceph/*.asok", "Ceph daemon admin sockets to connect.")
		ignoreSubsystems = flag.String("ceph.ignore", "AsyncMessenger,finisher,objectcacher,objecter-,prioritycache,recoverystate_perf,throttle", "Comma separated subsystem-prefixes to ignore")
	)

	flag.Parse()
	if *version {
		fmt.Printf("ceph-adm-exporter %v\n", Version)
		return
	}
	ignoredSubSystems = strings.Split(*ignoreSubsystems, ",")

	prometheus.MustRegister(NewCephADMCollector(*asokGlob))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Ceph ADM Exporter</title></head>
             <body>
             <h1>Ceph ADM Exporter ` + Version + `</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	http.Handle(*metricsPath, promhttp.Handler())
	log.Infof("ceph-adm-exporter %v listening on address %v", Version, *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Errorf("Error starting HTTP server %v", err)
		os.Exit(1)
	}
}
