// All agent logic is handled here
package main

import (
	"math"
	"math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

// The main  function for processing packets.
// If you want to build a custom handler, go here.
func inputProcessor(myIPAddress netip.Addr, isRouter bool, inchan <-chan inputPacket, outchan chan<- outputPacket) {
	var senderWG sync.WaitGroup

	for packet := range inchan {
		if packet.arpLayer != nil { // if arp
			if (routerMode && isRouter) || (!routerMode) {
				fromArpAddress, _ := netip.AddrFromSlice(packet.arpLayer.DstProtAddress)
				// is this request where is my IP ?
				if packet.arpLayer.Operation == layers.ARPRequest && myIPAddress == fromArpAddress {
					log.Debugf("Arp request: %v -> %v ", packet.etherLayer.SrcMAC, packet.etherLayer.DstMAC)

					ethernetLayer := &layers.Ethernet{
						SrcMAC:       myMAC,
						DstMAC:       packet.etherLayer.SrcMAC,
						EthernetType: layers.EthernetTypeARP,
					}
					arpLayer := &layers.ARP{
						AddrType:          packet.arpLayer.AddrType,
						Protocol:          packet.arpLayer.Protocol,
						SourceHwAddress:   myMAC, // using  MAC from global variable
						SourceProtAddress: myIPAddress.AsSlice(),
						DstHwAddress:      packet.arpLayer.SourceHwAddress,
						DstProtAddress:    packet.arpLayer.SourceProtAddress,
						Operation:         layers.ARPReply,
					}
					log.Debugf("Build ARP Reply %v at %v", arpLayer.DstProtAddress, arpLayer.DstHwAddress)
					out := buildPacket(ethernetLayer, arpLayer, nil, nil, nil)

					senderWG.Add(1)
					go func() {
						outchan <- out
						senderWG.Done()
					}()
				}
			}
		} else if packet.icmpLayer != nil { // Or is the ICMP packet ?
			log.Debug("Incoming ICMP")
			log.Debugf("MAC: %v -> %v ", packet.etherLayer.SrcMAC, packet.etherLayer.DstMAC)
			log.Debugf("IP: %s -> %s ", packet.ipLayer.SrcIP, packet.ipLayer.DstIP)
			log.Debugf("ICMP flow# %v, requence %v\n", packet.icmpLayer.Id, packet.icmpLayer.Seq)
			fromIPAddress, _ := netip.AddrFromSlice(packet.ipLayer.DstIP)

			if packet.icmpLayer.TypeCode.Type() == layers.ICMPv4TypeEchoRequest &&
				fromIPAddress == myIPAddress { // Did make a mistake when sending the package? Additional verification.
				loss := rand.Float64()
				if loss > packetLossRate {
					var replyBytes []byte
					// Assemble regular ICMP reply packet
					applicationLayer := packet.packet.ApplicationLayer()

					if applicationLayer != nil {
						replyBytes = applicationLayer.Payload()
					}

					icmpLayer := &layers.ICMPv4{
						TypeCode: layers.ICMPv4TypeEchoReply,
						Seq:      packet.icmpLayer.Seq,
						Id:       packet.icmpLayer.Id,
					}
					ipLayer := &layers.IPv4{
						SrcIP:    packet.ipLayer.DstIP,
						DstIP:    packet.ipLayer.SrcIP,
						Version:  4,
						TTL:      245,
						Protocol: layers.IPProtocolICMPv4,
					}
					ethernetLayer := &layers.Ethernet{
						SrcMAC:       packet.etherLayer.DstMAC,
						DstMAC:       packet.etherLayer.SrcMAC,
						EthernetType: layers.EthernetTypeIPv4,
					}
					out := buildPacket(ethernetLayer, nil, ipLayer, icmpLayer, replyBytes)
					sleepms := math.Round((float64(replyTimeoutMs) + rand.NormFloat64()*float64(replyStddevMs)))
					senderWG.Add(1)
					go func(out outputPacket) { // Even the same host must process packets independently, so we use goroutine.
						log.Tracef("Wait for %v ms", replyTimeoutMs)
						time.Sleep(time.Duration(sleepms) * time.Millisecond)
						outchan <- out
						senderWG.Done()
					}(out)

				}
			}
		}
	}
	senderWG.Wait()
	log.Trace("Handler exit ", myIPAddress)
}
