// All agent logic is handled here

// Tests likes https://github.com/google/gopacket/blob/master/layers/icmp6_test.go

package main

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// This data is taken from the packet dump
// To change this test, you will need to run a packet capture and copy the data using Wireshark
var testPacketARPRequest = []byte(
	"\xff\xff\xff\xff\xff\xff\x02\x42\xac\x14\x00\x02\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x02\x42\xac\x14\x00\x02\xac\x14\x00\x02\x00\x00\x00\x00\x00\x00\xac\x14\x00\x06",
)

func TestInputProcessorARP(t *testing.T) {

	inputMockChan := make(chan inputPacket)
	outputMockChan := make(chan outputPacket)

	replyTimeoutMs = 10
	replyStddevMs = 0
	packetLossRate = 0
	routerMode = true

	// mock mac address from packet dump
	myMAC = []byte("\x02\x42\xac\x14\x00\x06")

	p := gopacket.NewPacket(testPacketARPRequest, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}

	if arp, ok_parsed := p.Layer(layers.LayerTypeARP).(*layers.ARP); ok_parsed {
		etherLayer := p.Layer(layers.LayerTypeEthernet)
		ether, _ := etherLayer.(*layers.Ethernet)
		var mockPacket inputPacket
		mockPacket.packet = p
		mockPacket.arpLayer = arp
		mockPacket.etherLayer = ether
		myIpAddress, _ := netip.ParseAddr("172.20.0.6")
		go inputProcessor(myIpAddress, true, inputMockChan, outputMockChan)
		inputMockChan <- mockPacket
		replyPacket := <-outputMockChan
		replyGoPacket := gopacket.NewPacket(replyPacket.packetBytes, layers.LinkTypeEthernet, gopacket.Default)
		packet_ok := false
		if reply_arp, ok_parsed := replyGoPacket.Layer(layers.LayerTypeARP).(*layers.ARP); ok_parsed {
			if reply_arp.Operation == 0x2 &&
				bytes.Equal(reply_arp.SourceProtAddress, []uint8{172, 20, 0, 6}) &&
				bytes.Equal(reply_arp.DstProtAddress, []uint8{172, 20, 0, 2}) &&
				bytes.Equal(reply_arp.SourceHwAddress, []uint8("\x02B\xac\x14\x00\x06")) &&
				bytes.Equal(reply_arp.DstHwAddress, []uint8("\x02B\xac\x14\x00\x02")) {
				packet_ok = true
			}
		}
		if !packet_ok {
			t.Error("ARP Reply fail")
		}
	}
}

var testPacketICMPRequest = []byte(
	"\x02\x42\xac\x14\x00\x06\x02\x42\xac\x14\x00\x02\x08\x00\x45\x00\x00\x54\x4d\x05\x40\x00\x40\x01\x95\x6e\xac\x14\x00\x02\xac\x1e\x00\x01\x08\x00\xb6\xf3\x00\x07\x00\x01\xe3\xf1\x8d\x63\x00\x00\x00\x00\x05\xdc\x0b\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37",
)

// ICMP test.
func TestInputProcessorICMP(t *testing.T) {

	inputMockChan := make(chan inputPacket)
	outputMockChan := make(chan outputPacket)

	replyTimeoutMs = 10
	replyStddevMs = 0
	packetLossRate = 0
	routerMode = true

	// mock mac address from packet dump
	myMAC = []byte("\x02\x42\xac\x14\x00\x06")

	p := gopacket.NewPacket(testPacketICMPRequest, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}

	if icmp, ok_parsed := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok_parsed {
		etherLayer := p.Layer(layers.LayerTypeEthernet)
		ether, _ := etherLayer.(*layers.Ethernet)
		ipLayer := p.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)

		var mockPacket inputPacket
		mockPacket.packet = p
		mockPacket.icmpLayer = icmp
		mockPacket.ipLayer = ip
		mockPacket.etherLayer = ether
		myIpAddress, _ := netip.ParseAddr("172.30.0.1")
		go inputProcessor(myIpAddress, true, inputMockChan, outputMockChan)
		inputMockChan <- mockPacket
		replyPacket := <-outputMockChan
		replyGoPacket := gopacket.NewPacket(replyPacket.packetBytes, layers.LinkTypeEthernet, gopacket.Default)
		packet_ok := false
		if reply_ip, ok_parsed := replyGoPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok_parsed {
			if reply_icmp, ok_parsed := replyGoPacket.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok_parsed {
				if reply_icmp.TypeCode == 0x0 &&
					reply_icmp.Seq == 0x1 &&
					bytes.Equal(reply_ip.SrcIP, []uint8{172, 30, 0, 1}) &&
					bytes.Equal(reply_ip.DstIP, []uint8{172, 20, 0, 2}) {

					packet_ok = true
				}
			}
		}
		if !packet_ok {
			t.Error("ICMP Reply fail")
		}
	}
}
