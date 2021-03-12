// Copyright 2017 Kumina, https://kumina.nl/
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Project forked from https://github.com/kumina/libvirt_exporter
// And then forked from https://github.com/rumanzo/libvirt_exporter_improved
// And then forked from https://github.com/AlexZzz/libvirt-exporter

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	libvirtUpDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "", "up"),
		"Whether scraping libvirt's metrics was successful.",
		nil,
		nil)

	libvirtDomainInfoMetaDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_info", "meta"),
		"Domain metadata",
		[]string{"domain", "uuid"},
		nil)
	libvirtDomainInfoMaxMemBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_info", "maximum_memory_bytes"),
		"Maximum allowed memory of the domain, in bytes.",
		[]string{"domain"},
		nil)
	libvirtDomainInfoMemoryUnusedBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_info", "memory_unused_bytes"),
		"Unused memory of the domain, in bytes.",
		[]string{"domain"},
		nil)
	libvirtDomainInfoNrVirtCPUDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_info", "virtual_cpus"),
		"Number of virtual CPUs for the domain.",
		[]string{"domain"},
		nil)
	libvirtDomainInfoCPUTimeDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_info", "cpu_time_seconds_total"),
		"Amount of CPU time used by the domain, in seconds.",
		[]string{"domain"},
		nil)
	libvirtDomainInfoVirDomainState = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_info", "vstate"),
		"Virtual domain state. 0: no state, 1: the domain is running, 2: the domain is blocked on resource,"+
			" 3: the domain is paused by user, 4: the domain is being shut down, 5: the domain is shut off,"+
			"6: the domain is crashed, 7: the domain is suspended by guest power management",
		[]string{"domain", "state"},
		nil)

	libvirtDomainVcpuTimeDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_vcpu", "time_seconds_total"),
		"Amount of CPU time used by the domain's VCPU, in seconds.",
		[]string{"domain", "vcpu"},
		nil)
	libvirtDomainVcpuStateDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_vcpu", "state"),
		"VCPU state. 0: offline, 1: running, 2: blocked",
		[]string{"domain", "vcpu"},
		nil)

	libvirtDomainBlockRdBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "read_bytes_total"),
		"Number of bytes read from a block device, in bytes.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockRdReqDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "read_requests_total"),
		"Number of read requests from a block device.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockRdTotalTimeSecondsDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "read_time_seconds_total"),
		"Total time spent on reads from a block device, in seconds.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockWrBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "write_bytes_total"),
		"Number of bytes written to a block device, in bytes.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockWrReqDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "write_requests_total"),
		"Number of write requests to a block device.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockWrTotalTimesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "write_time_seconds_total"),
		"Total time spent on writes on a block device, in seconds",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockFlushReqDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "flush_requests_total"),
		"Total flush requests from a block device.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockFlushTotalTimeSecondsDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "flush_time_seconds_total"),
		"Total time in seconds spent on cache flushing to a block device",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockAllocationDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "allocation"),
		"Offset of the highest written sector on a block device.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockCapacityBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "capacity_bytes"),
		"Logical size in bytes of the block device	backing image.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockPhysicalSizeBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_block_stats", "physicalsize_bytes"),
		"Physical size in bytes of the container of the backing image.",
		[]string{"domain", "target_device"},
		nil)

	libvirtDomainMetaInterfacesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface", "meta"),
		"Interfaces metadata. Source bridge, target device, interface uuid",
		[]string{"domain", "source_bridge", "target_device", "virtual_interface"},
		nil)
	libvirtDomainInterfaceRxBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_bytes_total"),
		"Number of bytes received on a network interface, in bytes.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceRxPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_packets_total"),
		"Number of packets received on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceRxErrsDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_errors_total"),
		"Number of packet receive errors on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceRxDropDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface_stats", "receive_drops_total"),
		"Number of packet receive drops on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceTxBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_bytes_total"),
		"Number of bytes transmitted on a network interface, in bytes.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceTxPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_packets_total"),
		"Number of packets transmitted on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceTxErrsDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_errors_total"),
		"Number of packet transmit errors on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceTxDropDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_interface_stats", "transmit_drops_total"),
		"Number of packet transmit drops on a network interface.",
		[]string{"domain", "target_device"},
		nil)

	libvirtDomainMemoryStatMajorFaultTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_memory_stats", "major_fault_total"),
		"Page faults occur when a process makes a valid access to virtual memory that is not available. "+
			"When servicing the page fault, if disk IO is required, it is considered a major fault.",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatMinorFaultTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_memory_stats", "minor_fault_total"),
		"Page faults occur when a process makes a valid access to virtual memory that is not available. "+
			"When servicing the page not fault, if disk IO is required, it is considered a minor fault.",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatUnusedBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_memory_stats", "unused_bytes"),
		"The amount of memory left completely unused by the system. Memory that is available but used for "+
			"reclaimable caches should NOT be reported as free. This value is expressed in bytes.",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatAvailableBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_memory_stats", "available_bytes"),
		"The total amount of usable memory as seen by the domain. This value may be less than the amount of "+
			"memory assigned to the domain if a balloon driver is in use or if the guest OS does not initialize all "+
			"assigned pages. This value is expressed in bytes.",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatRssBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_memory_stats", "rss_bytes"),
		"Resident Set Size of the process running the domain. This value is in bytes",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatUsedPercentDesc = prometheus.NewDesc(
		prometheus.BuildFQName("libvirt", "domain_memory_stats", "used_percent"),
		"The amount of memory in percent, that used by domain.",
		[]string{"domain"},
		nil)
	)

// HasPrefixAndSuffix checks if a string has the specified prefix and suffix
func HasPrefixAndSuffix(str string, prefix string, suffix string) bool {
	return strings.HasPrefix(str, prefix) && strings.HasSuffix(str, suffix)
}

// GetVirtStateStr Retrurns a description of the state associated with the supplied numerical state
func GetVirtStateStr(numVal int32) string {
	switch (numVal) {
		case 1: return "ok"
		case 2: return "blocked-on-resource"
		case 3: return "paused"
		case 4: return "shutting-down"
		case 5: return "shut-down"
		case 6: return "crashed"
		case 7: return "suspended-by-power-mgmt"
		case 0: fallthrough
		default: 
			return "unknown"
	}
}

// CollectDomain extracts Prometheus metrics from a libvirt domain.
func CollectDomain(ch chan<- prometheus.Metric, domRec libvirt.DomainStatsRecord) error {
	domainName := domRec.Dom.Name
	domainUUID := fmt.Sprint(domRec.Dom.UUID)

	ch <- prometheus.MustNewConstMetric(
		libvirtDomainInfoMetaDesc,
		prometheus.GaugeValue,
		float64(1),
		domainName,
		domainUUID)

	var totalMemory, unusedMemory float64
	var currDiskName, currIfaceName string
	for _, stat := range domRec.Params {
		if stat.Field == "balloon.available" {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInfoMaxMemBytesDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint64))*1024,
				domainName)
		} else if stat.Field == "balloon.unused" {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInfoMemoryUnusedBytesDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint64))*1024,
				domainName)
		}
		
		if stat.Field == "vcpu.maximum" {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInfoNrVirtCPUDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint32)),
				domainName)
		} else if stat.Field == "cpu.time" {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInfoCPUTimeDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64))/1000/1000/1000, // From nsec to sec
				domainName)
		} else if stat.Field == "state.state" {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInfoVirDomainState,
				prometheus.GaugeValue,
				float64(stat.Value.I.(int32)),
				domainName,
				GetVirtStateStr(stat.Value.I.(int32)))
		} else if HasPrefixAndSuffix(stat.Field, "vcpu.", ".state") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainVcpuStateDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(int32)),
				domainName,
				string(stat.Field[5])) // 5th char in field name is vcpu #
		} else if HasPrefixAndSuffix(stat.Field, "vcpu.", ".time") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainVcpuTimeDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64))/1000/1000/1000, // From nsec to sec
				domainName,
				string(stat.Field[5]))
		} else if HasPrefixAndSuffix(stat.Field, "block.", ".name") {
			currDiskName = fmt.Sprint(stat.Value.I)
		} else if HasPrefixAndSuffix(stat.Field, "block.", ".rd.bytes") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockRdBytesDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", ".rd.reqs") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockRdReqDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", "rd.times") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockRdTotalTimeSecondsDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64))/1e9,
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", "wr.bytes") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockWrBytesDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", "wr.reqs") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockWrReqDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", "wr.times") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockWrTotalTimesDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64))/1e9,
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", "fl.reqs") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockFlushReqDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", "fl.times") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockFlushTotalTimeSecondsDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64))/1e9,
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", ".allocation") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockAllocationDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", ".capacity") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockCapacityBytesDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "block.", ".physical") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainBlockPhysicalSizeBytesDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currDiskName)
		} else if HasPrefixAndSuffix(stat.Field, "net.", ".name") {
			currIfaceName = fmt.Sprint(stat.Value.I)
		} else if HasPrefixAndSuffix(stat.Field, "net.", ".rx.bytes") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInterfaceRxBytesDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currIfaceName)
		} else if HasPrefixAndSuffix(stat.Field, "net.", ".rx.pkts") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInterfaceRxPacketsDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currIfaceName)
		} else if HasPrefixAndSuffix(stat.Field, "net.", "rx.errs") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInterfaceRxErrsDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currIfaceName)
		} else if HasPrefixAndSuffix(stat.Field, "net.", "rx.drop") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInterfaceRxDropDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currIfaceName)
		} else if HasPrefixAndSuffix(stat.Field, "net.", "tx.bytes") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInterfaceTxBytesDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currIfaceName)
		} else if HasPrefixAndSuffix(stat.Field, "net.", "tx.pkts") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInterfaceTxPacketsDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currIfaceName)
		} else if HasPrefixAndSuffix(stat.Field, "net.", "tx.errs") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInterfaceTxErrsDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currIfaceName)
		} else if HasPrefixAndSuffix(stat.Field, "net.", "tx.drop") {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainInterfaceTxDropDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName,
				currIfaceName)
		} else if stat.Field == "balloon.major_fault" {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatMajorFaultTotalDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName)
		} else if stat.Field == "balloon.minor_fault" {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatMinorFaultTotalDesc,
				prometheus.CounterValue,
				float64(stat.Value.I.(uint64)),
				domainName)
		} else if stat.Field == "balloon.unused" {
			unusedMemory = float64(stat.Value.I.(uint64))*1024
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatUnusedBytesDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint64))*1024,
				domainName)
		} else if stat.Field == "balloon.available" {
			totalMemory = float64(stat.Value.I.(uint64))*1024
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatAvailableBytesDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint64))*1024,
				domainName)
		} else if stat.Field == "balloon.rss" {
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatRssBytesDesc,
				prometheus.GaugeValue,
				float64(stat.Value.I.(uint64))*1024,
				domainName)
		}
	}

	usedPercent := (totalMemory - unusedMemory) / totalMemory

	ch <- prometheus.MustNewConstMetric(
		libvirtDomainMemoryStatUsedPercentDesc,
		prometheus.GaugeValue,
		float64(usedPercent),
		domainName)
	
	return nil
}

// Describe returns metadata for all Prometheus metrics that may be exported.
func (e *LibvirtExporter) Describe(ch chan<- *prometheus.Desc) {
	// Status
	ch <- libvirtUpDesc

	// Domain info
	ch <- libvirtDomainInfoMetaDesc
	ch <- libvirtDomainInfoMaxMemBytesDesc
	ch <- libvirtDomainInfoMemoryUnusedBytesDesc
	ch <- libvirtDomainInfoNrVirtCPUDesc
	ch <- libvirtDomainInfoCPUTimeDesc
	ch <- libvirtDomainInfoVirDomainState

	// VCPU info
	ch <- libvirtDomainVcpuStateDesc
	ch <- libvirtDomainVcpuTimeDesc

	// Domain block stats
	ch <- libvirtDomainBlockRdBytesDesc
	ch <- libvirtDomainBlockRdReqDesc
	ch <- libvirtDomainBlockRdTotalTimeSecondsDesc
	ch <- libvirtDomainBlockWrBytesDesc
	ch <- libvirtDomainBlockWrReqDesc
	ch <- libvirtDomainBlockWrTotalTimesDesc
	ch <- libvirtDomainBlockFlushReqDesc
	ch <- libvirtDomainBlockFlushTotalTimeSecondsDesc
	ch <- libvirtDomainBlockAllocationDesc
	ch <- libvirtDomainBlockCapacityBytesDesc
	ch <- libvirtDomainBlockPhysicalSizeBytesDesc

	// Domain net interfaces stats
	ch <- libvirtDomainMetaInterfacesDesc
	ch <- libvirtDomainInterfaceRxBytesDesc
	ch <- libvirtDomainInterfaceRxPacketsDesc
	ch <- libvirtDomainInterfaceRxErrsDesc
	ch <- libvirtDomainInterfaceRxDropDesc
	ch <- libvirtDomainInterfaceTxBytesDesc
	ch <- libvirtDomainInterfaceTxPacketsDesc
	ch <- libvirtDomainInterfaceTxErrsDesc
	ch <- libvirtDomainInterfaceTxDropDesc

	// Domain memory stats
	ch <- libvirtDomainMemoryStatMajorFaultTotalDesc
	ch <- libvirtDomainMemoryStatMinorFaultTotalDesc
	ch <- libvirtDomainMemoryStatUnusedBytesDesc
	ch <- libvirtDomainMemoryStatAvailableBytesDesc
	ch <- libvirtDomainMemoryStatRssBytesDesc
}

// elapsed Run with defered to print how long function took to execute
func elapsed(what string) func() {
    start := time.Now()
    return func() {
        fmt.Printf("%s took %v\n", what, time.Since(start))
    }
}

// LibvirtExporter Contains data to connect to libvirt daemon
type LibvirtExporter struct {
	protocol string
	uri string
}

// NewLibvirtExporter creates a new Prometheus exporter for libvirt.
func NewLibvirtExporter(uri string, protocol string) (*LibvirtExporter, error) {
	return &LibvirtExporter{
		uri: uri,
		protocol: protocol,
	}, nil
}

// Collect scrapes Prometheus metrics from libvirt.
func (e *LibvirtExporter) Collect(ch chan<- prometheus.Metric) {
	defer elapsed("Collect")()
	err := CollectFromLibvirt(ch, e)
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			libvirtUpDesc,
			prometheus.GaugeValue,
			1.0)
	} else {
		log.Printf("Failed to scrape metrics: %s", err)
		ch <- prometheus.MustNewConstMetric(
			libvirtUpDesc,
			prometheus.GaugeValue,
			0.0)
	}
}

// CollectFromLibvirt obtains Prometheus metrics from all domains in a
// libvirt setup.
func CollectFromLibvirt(ch chan<- prometheus.Metric, e *LibvirtExporter) error {
	conn, err := net.DialTimeout(e.protocol, e.uri, 2*time.Second)
	if err != nil {
		return err
	}
	l := libvirt.New(conn)
	if err := l.Connect(); err != nil {
		return err
	}

	defer conn.Close()
	
	domains, err := l.Domains()
	if err != nil {
		return err
	}
	
	stats, err := l.ConnectGetAllDomainStats(domains, uint32(libvirt.DomainStatsState | libvirt.DomainStatsCPUTotal | libvirt.DomainStatsVCPU | libvirt.DomainStatsInterface | libvirt.DomainStatsBalloon | libvirt.DomainStatsBlock), 0);
	if err != nil {
		return err
	}
	for _, stat := range stats {
		err = CollectDomain(ch, stat)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	var (
		app = kingpin.New("libvirt_exporter", "Prometheus metrics exporter for libvirt")
		listenAddress = app.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9177").String()
		metricsPath = app.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		libvirtProtocol = app.Flag("libvirt.protocol", "Libvirt protocol with which to connect to the daemon (unix/tcp)").Default("unix").String()
		libvirtURI = app.Flag("libvirt.uri", "Libvirt URI from which to extract metrics.").Default("/var/run/libvirt/libvirt-sock-ro").String()
	)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	exporter, err := NewLibvirtExporter(*libvirtURI, *libvirtProtocol)
	if err != nil {
		log.Fatalf("failed to create exporter instance: %v", err)
		panic(err)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>Libvirt Exporter</title></head>
			<body>
			<h1>Libvirt Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
