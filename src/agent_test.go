// All agent logic is handled here

// Tests likes https://github.com/google/gopacket/blob/master/layers/icmp6_test.go

package main

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// This data is taken from the packet dump
// To change this test, you will need to run a packet capture and copy the data using Wireshark

func TestInputProcessorARP(t *testing.T) {
	var testPacketARPRequest = []byte(
		"\xff\xff\xff\xff\xff\xff\x02\x42\xac\x14\x00\x02\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x02\x42\xac\x14\x00\x02\xac\x14\x00\x02\x00\x00\x00\x00\x00\x00\xac\x14\x00\x06",
	)

	// This function tests first packet from channel with timeout! Change this in cause of debugging
	const secondsTimeout = 2

	inputMockChan := make(chan inputPacket)
	outputMockChan := make(chan outputPacket)

	replyTimeoutMs = 10
	replyStddevMs = 0
	packetLossRate = 0
	routerMode = true

	// mock mac address from packet dump
	myMAC = []byte("\x02\x42\xac\x14\x00\x06")

	inPacket := gopacket.NewPacket(testPacketARPRequest, layers.LinkTypeEthernet, gopacket.Default)
	if inPacket.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", inPacket.ErrorLayer().Error())
	}

	if arp, parsedOk := inPacket.Layer(layers.LayerTypeARP).(*layers.ARP); parsedOk {
		var (
			mockPacketStruct inputPacket
			replyPacket      outputPacket
		)

		etherLayer := inPacket.Layer(layers.LayerTypeEthernet)
		ether, _ := etherLayer.(*layers.Ethernet)

		mockPacketStruct.packet = inPacket
		mockPacketStruct.arpLayer = arp
		mockPacketStruct.etherLayer = ether
		myIPAddress, _ := netip.ParseAddr("172.20.0.6")

		go inputProcessor(myIPAddress, true, inputMockChan, outputMockChan)
		inputMockChan <- mockPacketStruct

		timeout := time.After(secondsTimeout * time.Second)
		select {
		case <-timeout: // guard timeout
			t.Fatalf("function din't reply in %v seconds", secondsTimeout)
		case replyPacket = <-outputMockChan: // normal reply
		}

		if len(replyPacket.packetBytes) == 0 {
			t.Error("Packet reply size == 0")
		}

		replyGoPacket := gopacket.NewPacket(replyPacket.packetBytes, layers.LinkTypeEthernet, gopacket.Default)
		packetOK := false

		if replyArp, parsedOk := replyGoPacket.Layer(layers.LayerTypeARP).(*layers.ARP); parsedOk {
			if replyArp.Operation == 0x2 &&
				bytes.Equal(replyArp.SourceProtAddress, []uint8{172, 20, 0, 6}) &&
				bytes.Equal(replyArp.DstProtAddress, []uint8{172, 20, 0, 2}) &&
				bytes.Equal(replyArp.SourceHwAddress, []uint8("\x02B\xac\x14\x00\x06")) &&
				bytes.Equal(replyArp.DstHwAddress, []uint8("\x02B\xac\x14\x00\x02")) {
				packetOK = true
			}
		}

		if !packetOK {
			t.Error("ARP Reply Headers incorrect")
		}
	}
}

// ICMP test.
func TestInputProcessorICMP(t *testing.T) {
	var testPacketICMPRequest = []byte(
		"\x02\x42\xac\x14\x00\x06\x02\x42\xac\x14\x00\x02\x08\x00\x45\x00\x00\x54\x4d\x05\x40\x00\x40\x01\x95\x6e\xac\x14\x00\x02\xac\x1e\x00\x01\x08\x00\xb6\xf3\x00\x07\x00\x01\xe3\xf1\x8d\x63\x00\x00\x00\x00\x05\xdc\x0b\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37",
	)

	// This function tests first packet from channel with timeout! Change this in cause of debugging
	const secondsTimeout = 2

	inputMockChan := make(chan inputPacket)
	outputMockChan := make(chan outputPacket)

	replyTimeoutMs = 10
	replyStddevMs = 0
	packetLossRate = 0
	routerMode = true

	// mock mac address from packet dump
	myMAC = []byte("\x02\x42\xac\x14\x00\x06")

	inPacket := gopacket.NewPacket(testPacketICMPRequest, layers.LinkTypeEthernet, gopacket.Default)
	if inPacket.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", inPacket.ErrorLayer().Error())
	}

	if icmp, parsedOk := inPacket.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); parsedOk {
		var (
			mockPacket  inputPacket
			replyPacket outputPacket
		)

		etherLayer := inPacket.Layer(layers.LayerTypeEthernet)
		ether, _ := etherLayer.(*layers.Ethernet)
		ipLayer := inPacket.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)

		mockPacket.packet = inPacket
		mockPacket.icmpLayer = icmp
		mockPacket.ipLayer = ip
		mockPacket.etherLayer = ether
		myIPAddress, _ := netip.ParseAddr("172.30.0.1")

		go inputProcessor(myIPAddress, true, inputMockChan, outputMockChan)

		inputMockChan <- mockPacket

		timeout := time.After(secondsTimeout * time.Second)
		select {
		case <-timeout: // guard timeout
			t.Fatalf("function din't reply in %v seconds", secondsTimeout)
		case replyPacket = <-outputMockChan: // normal reply
		}

		if len(replyPacket.packetBytes) == 0 {
			t.Error("Packet reply size == 0")
		}

		if len(replyPacket.packetBytes) == 0 {
			t.Error("Packet reply size == 0")
		}

		replyGoPacket := gopacket.NewPacket(replyPacket.packetBytes, layers.LinkTypeEthernet, gopacket.Default)
		packetOk := false

		if replyIP, parsedOk := replyGoPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4); parsedOk {
			if replyICMP, parsedOk := replyGoPacket.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); parsedOk {
				if replyICMP.TypeCode == 0x0 &&
					replyICMP.Seq == 0x1 &&
					bytes.Equal(replyIP.SrcIP, []uint8{172, 30, 0, 1}) &&
					bytes.Equal(replyIP.DstIP, []uint8{172, 20, 0, 2}) {
					packetOk = true
				}
			}
		}

		if !packetOk {
			t.Error("ICMP Reply Headers incorrect")
		}
	}
}
