/*
	A program that sends responses to pings on behalf of non-existent hosts.
	Host simulator prototype for monitoring systems benchmark.

	github.com/pavlozt

*/

package main

import (
	"flag"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"go4.org/netipx" // non-standard library, but cool.
)

var (
	devicename             = "eth0"
	snapshotLen      int32 = 1024
	promiscuous            = true
	pcapHandle       *pcap.Handle
	myMAC            []byte
	ipRangeString    string
	ipRange          netipx.IPRange
	simulateRouter   string
	loglevel         string
	routerMode       = false
	addressTable     map[netip.Addr]chan inputPacket
	globalPacketChan chan gopacket.Packet
	outputChannel    chan outputPacket

	exitWG sync.WaitGroup // global WaitGroup for graceful shutdown

	replyTimeoutMs uint
	replyStddevMs  uint
	packetLossRate float64
)

// We use a structure for transmitting packets with additional fields to eliminate double work
// Some of the fields in any case must be parsed by the packet router.
// The original package structure is also transferred.
type inputPacket struct {
	packet     gopacket.Packet
	etherLayer *layers.Ethernet
	arpLayer   *layers.ARP
	ipLayer    *layers.IPv4
	icmpLayer  *layers.ICMPv4
}

// Separate type for outgoing packets
// you may need to send additional features, but only packet bytes are sent now
type outputPacket struct {
	packetBytes []uint8
}

// Single package assembly point
func buildPacket(
	ethernetLayer gopacket.SerializableLayer,
	arpLayer gopacket.SerializableLayer,
	ipLayer gopacket.SerializableLayer,
	icmpLayer gopacket.SerializableLayer,
	payloadBytes []byte) outputPacket {

	var buffer gopacket.SerializeBuffer
	var out outputPacket

	buffer = gopacket.NewSerializeBuffer()
	serializationOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Now there are two build variants arp and ICMP
	var serialError error
	if arpLayer != nil {
		serialError = gopacket.SerializeLayers(buffer, serializationOptions,
			ethernetLayer,
			arpLayer,
			//  arp does not need payload
		)
	} else if icmpLayer != nil {
		serialError = gopacket.SerializeLayers(buffer, serializationOptions,
			ethernetLayer,
			ipLayer,
			icmpLayer,
			gopacket.Payload(payloadBytes),
		)
	}
	if serialError == nil {
		out.packetBytes = buffer.Bytes()
	}
	return out

}

// Sending all prepared packets to the network in one stream
func toNetworkSender(out <-chan outputPacket, pcapHandler *pcap.Handle) {
	exitWG.Add(1) // global WaitGroup for graceful shutdown
	defer exitWG.Done()
	for reply := range out {
		log.Traceln(reply.packetBytes)
		err := pcapHandle.WritePacketData(reply.packetBytes)
		if err != nil {
			log.Fatal(err)
		}

	}
}

// Initialization
func globalInit() {
	flag.StringVar(&simulateRouter, "simulaterouter", "", "Router IP for simulation. If used, program simulate router. If absent, simulate bridged network.")
	flag.StringVar(&ipRangeString, "iprange", "", "IP range for simulation. (For example 172.26.0.1-172.26.0.254)")
	flag.UintVar(&replyTimeoutMs, "timeout", 200, "Reply timeout for ping reply in milliseconds.")
	flag.UintVar(&replyStddevMs, "replystddev", 0, "Reply standart deviation in milliseconds.")
	flag.Float64Var(&packetLossRate, "packetlossrate", 0.0, "Packet loss rate. Float number from 0.0 to 1.0")
	flag.StringVar(&loglevel, "loglevel", "error", "Log level(fatal, error, warning, debug, trace)")
	flag.StringVar(&devicename, "iface", "eth0", "Interface name")
	flag.Parse()
	ll, err := log.ParseLevel(loglevel)
	if err != nil {
		ll = log.ErrorLevel
	}
	log.SetLevel(ll)
	if ipRangeString == "" {
		log.Fatal("ip parameter required")
	}
	ipRange, err = netipx.ParseIPRange(ipRangeString)
	if err != nil {
		log.Fatal("Cant' parse ip range")
	}

	rand.Seed(time.Now().UnixNano())

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGQUIT)
	go shutDown(signalChannel)
}

// Special Shutdown hander
func shutDown(signalChannel chan os.Signal) {
	<-signalChannel
	log.Debugln("Shutdown.")
	close(globalPacketChan)
	for ip, readChannel := range addressTable {
		log.Traceln("closing ", ip.String())
		close(readChannel)
	}
	close(outputChannel)
	pcapHandle.Close()
}

// Main program
func main() {
	globalInit()
	myRouterAddress, err := netip.ParseAddr(simulateRouter)
	if err == nil && !myRouterAddress.IsUnspecified() {
		routerMode = true
	}
	iface, err := net.InterfaceByName(devicename)
	if err != nil {
		log.Fatal("no interfaces. Stop.")
	}
	myMAC = iface.HardwareAddr
	log.Debug("Using device MAC ", iface.HardwareAddr.String())
	pcapHandle, _ = pcap.OpenLive(devicename, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	if pcapHandle == nil {
		log.Fatal("Can't open capture interface. (Need root capabilities?)")
	}
	log.Debug("Live capture interfaces opened")

	var filter = "arp or (icmp and icmp[icmptype] != icmp-echoreply)"
	err = pcapHandle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	log.Debugf("Capturing with filter \"%s\"", filter)
	if routerMode {
		log.Debugf("Mode: router (%v) with single arp reply", myRouterAddress)
	} else {
		log.Debug("Mode: bridge with broadcast arp reply")
	}
	log.Debugf("Reply IP range %s", ipRange)

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	outputChannel = make(chan outputPacket)
	addressTable = make(map[netip.Addr]chan inputPacket)
	for ip := ipRange.From(); ip.Compare(ipRange.To()) <= 0; ip = ip.Next() {
		log.Traceln("New channel for ip:", ip)
		// Do We need to redo thread creation only when a new packet arrives?
		// (in this case a mutex would be needed)
		// for ease of processing, now we create all the channels at the start.
		agentInputChannel := make(chan inputPacket)
		addressTable[ip] = agentInputChannel
		go inputProcessor(ip, false, agentInputChannel, outputChannel) // host(s)
	}

	inputRouterChannel := make(chan inputPacket)
	if routerMode {
		log.Traceln("New channel for ip:", myRouterAddress)
		addressTable[myRouterAddress] = inputRouterChannel
		go inputProcessor(myRouterAddress, true, inputRouterChannel, outputChannel) // router
	}

	go toNetworkSender(outputChannel, pcapHandle) // always need reply sender
	globalPacketChan = packetSource.Packets()
	for packet := range globalPacketChan {
		etherLayer := packet.Layer(layers.LayerTypeEthernet)
		ether, _ := etherLayer.(*layers.Ethernet)
		arpLayer := packet.Layer(layers.LayerTypeARP)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		var inputStruct inputPacket
		inputStruct.packet = packet
		inputStruct.etherLayer = ether

		log.Tracef("Input packet %v", packet)

		// An IP is extracted from the incoming packet and a match is searched in the table (map) of addresses.
		// Packets of any type are sent to the goroutine handler.

		// There are two modes of program operation - router and bridge
		// In bridge mode, handlers must respond to both arp and IP
		// In router mode, handlers only respond to IP, and arp should be ignored
		// For this, an argument is passed to the goroutine.
		var dstAddr netip.Addr
		// both packets ICMP and  broadcast ARP requests to "our" IPs should be intercepted
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPRequest {
				inputStruct.arpLayer = arp
				dstAddr, _ = netip.AddrFromSlice(arp.DstProtAddress)
			}
		}
		if icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
				inputStruct.ipLayer = ip
				inputStruct.icmpLayer = icmp
				dstAddr, _ = netip.AddrFromSlice(ip.DstIP)
			}
		}
		if !dstAddr.IsUnspecified() {
			inputChan, exists := addressTable[dstAddr]
			if exists {
				inputChan <- inputStruct
			}

		}
	}
	// Shutdown function closes all opened handles and channels
	log.Traceln("waiting for all and sync group")
	exitWG.Wait()
}
