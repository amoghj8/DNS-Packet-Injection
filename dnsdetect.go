package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/facebookgo/subset"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	bpfFilter     string = ""
	handle        *pcap.Handle
	interfaceName string        = ""
	snapshotLen   int32         = 1600
	timeout       time.Duration = pcap.BlockForever
	ethernetLayer layers.Ethernet
	ipv4Layer     layers.IPv4
	udpLayer      layers.UDP
	dnsLayer      layers.DNS
	dnsRecord     layers.DNSResourceRecord
	dnsQuestions  layers.DNSQuestion
	i             uint16
	ipv4Addr      net.IP
	udpPort       layers.UDPPort
	ethernetMAC   net.HardwareAddr
	rFlag		  *string
	iFlag		  *string
	ip			  net.IP
	idPacketMap = make(map[uint16]gopacket.Packet)
)

func main() {

	// -i flag is used to specify the network device interface
	iFlag = flag.String("i", "", "Interface to listen and inject packets")
	// -r flag is used to read packets from a tracefile
	rFlag = flag.String("r", "", "Read packets from given tracefile")

	flag.Parse()

	// Storing the BPF string to be applied
	bpfFilter = strings.Join(flag.Args(), " ")

	if *rFlag != "" {
		detectFromTracefile()
	} else {
		detectFromInterface()
	}

}

// Spoof detection live from interface
func detectFromInterface() {

	if *iFlag=="" {
		ip = getDefaultIP()
		interfaceName = getDefaultInterface()
	} else {
		ip = getInterfaceIP(*iFlag)
		interfaceName = getInterfaceName()
	}

	handle, error := pcap.OpenLive(interfaceName, snapshotLen, true, timeout)

	if error != nil {
		panic(error)
	}

	defer handle.Close()

	if bpfFilter != "" {
		err := handle.SetBPFFilter(bpfFilter)
		if err != nil {
			panic(err)
		}
	} else {
		err := handle.SetBPFFilter("udp and port 53")
		if err != nil {
			panic(err)
		}
	}

	handleDNSSpoof(handle)

}

// Spoof detection from existing packet tracefile
func detectFromTracefile() {

	if handle, err := pcap.OpenOffline(*rFlag); err != nil {
		panic(err)
	} else {
		if bpfFilter != "" {
			err := handle.SetBPFFilter(bpfFilter)
			if err != nil {
				panic(err)
			}
		}
		handleDNSSpoof(handle)

	}

}

// Common Handler for DNS Spoof
func handleDNSSpoof(handle *pcap.Handle) {

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernetLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	parsedLayers := make([]gopacket.LayerType, 0, 4)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		err := parser.DecodeLayers(packet.Data(), &parsedLayers)
		if err != nil {
			continue
		}

		// Verify if all 4 layers are decoded
		if len(parsedLayers) != 4 {
			continue
		}

		// We only require responses so discarding queries
		if dnsLayer.QR==false {
			continue
		}

		// Check if packet already present with transaction id else compare with existing packet for spoof
		existingPacket, isPresent := idPacketMap[dnsLayer.ID]
		if !isPresent {
			idPacketMap[dnsLayer.ID] = packet
		} else {
			if isDNSSpoof(packet, existingPacket)==true {
				printSpoofedResponse(packet, existingPacket)
			}
		}
	}
}

// Returns true if dns spoof is detected else returns false
func isDNSSpoof(newPacket gopacket.Packet , existingPacket gopacket.Packet) bool {
	var ethernetLayerResponse1 layers.Ethernet
	var ethernetLayerResponse2 layers.Ethernet
	var ipv4LayerResponse1     layers.IPv4
	var ipv4LayerResponse2     layers.IPv4
	var udpLayerResponse1      layers.UDP
	var udpLayerResponse2      layers.UDP
	var dnsLayerResponse1     layers.DNS
	var dnsLayerResponse2     layers.DNS
	decoder1 := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernetLayerResponse1, &ipv4LayerResponse1,
		&udpLayerResponse1, &dnsLayerResponse1)
	decodedLayers1 := make([]gopacket.LayerType, 0, 4)
	decoder2 := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernetLayerResponse2, &ipv4LayerResponse2,
		&udpLayerResponse2, &dnsLayerResponse2)
	decodedLayers2 := make([]gopacket.LayerType, 0, 4)
	decoder1.DecodeLayers(newPacket.Data(), &decodedLayers1)
	decoder2.DecodeLayers(existingPacket.Data(), &decodedLayers2)

	if udpLayerResponse1.DstPort==udpLayerResponse2.DstPort && ipv4LayerResponse1.DstIP.String()==ipv4LayerResponse2.DstIP.String() && udpLayerResponse1.SrcPort.String()==udpLayerResponse2.SrcPort.String() && ipv4LayerResponse1.SrcIP.String()==ipv4LayerResponse2.SrcIP.String(){
		var existingIPs []string
		var existingTTLs []uint32
		var newIPs []string
		var newTTLs []uint32

		for i=0;i<dnsLayerResponse1.ANCount;i++ {
			if dnsLayerResponse1.Answers[i].Type==layers.DNSTypeA {
				newIPs = append(newIPs, dnsLayerResponse1.Answers[i].IP.String())
				newTTLs = append(newTTLs, dnsLayerResponse1.Answers[i].TTL)
			}
		}
		for i=0;i<dnsLayerResponse2.ANCount;i++ {
			if dnsLayerResponse2.Answers[i].Type==layers.DNSTypeA {
				existingIPs = append(existingIPs, dnsLayerResponse2.Answers[i].IP.String())
				existingTTLs = append(existingTTLs, dnsLayerResponse2.Answers[i].TTL)
			}
		}

		// Check false positive case for load balanced IPs
		if subset.Check(newIPs, existingIPs) {
			return false
		}

		// Check false positive using TTLs as its highly unlikely for attacker to have guessed correct TTLs
		if subset.Check(newTTLs, existingTTLs) {
			return false
		}

		return true

	} else {
		return false
	}
}

// Printing the spoofed packet details
func printSpoofedResponse(newPacket gopacket.Packet , existingPacket gopacket.Packet) {

	var ethernetLayerResponse1 layers.Ethernet
	var ethernetLayerResponse2 layers.Ethernet
	var ipv4LayerResponse1     layers.IPv4
	var ipv4LayerResponse2     layers.IPv4
	var udpLayerResponse1      layers.UDP
	var udpLayerResponse2      layers.UDP
	var dnsLayerResponse1     layers.DNS
	var dnsLayerResponse2     layers.DNS

	decoder1 := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernetLayerResponse1, &ipv4LayerResponse1,
		&udpLayerResponse1, &dnsLayerResponse1)
	decodedLayers1 := make([]gopacket.LayerType, 0, 4)
	decoder2 := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernetLayerResponse2, &ipv4LayerResponse2,
		&udpLayerResponse2, &dnsLayerResponse2)
	decodedLayers2 := make([]gopacket.LayerType, 0, 4)

	decoder1.DecodeLayers(newPacket.Data(), &decodedLayers1)
	decoder2.DecodeLayers(existingPacket.Data(), &decodedLayers2)

	fmt.Println(newPacket.Metadata().Timestamp.String() + " DNS poisoning attempt")
	fmt.Printf("TXID 0x" + strconv.FormatInt(int64(dnsLayerResponse1.ID), 16)  + " Request " +
				string(dnsLayerResponse1.Questions[0].Name))
	fmt.Println()
	fmt.Print("Answer1 ")
	for i = 0; i < dnsLayerResponse1.ANCount; i++ {
		if dnsLayerResponse1.Answers[i].Type==layers.DNSTypeA {
			fmt.Print(dnsLayerResponse1.Answers[i].IP)
		} else if dnsLayerResponse1.Answers[i].Type==layers.DNSTypeCNAME {
			fmt.Print(string(dnsLayerResponse1.Answers[i].CNAME))
		}
		fmt.Print(" ")
	}

	fmt.Print("Answer2 ")
	for i = 0; i < dnsLayerResponse2.ANCount; i++ {
		if dnsLayerResponse2.Answers[i].Type==layers.DNSTypeA {
			fmt.Print(dnsLayerResponse2.Answers[i].IP)
		} else if dnsLayerResponse2.Answers[i].Type==layers.DNSTypeCNAME {
			fmt.Printf("%s", string(dnsLayerResponse2.Answers[i].CNAME))
		}
		fmt.Print(" ")
	}
	fmt.Println()
}

// Get IP address of interface eth0 or first ip address available if no eth0
func getDefaultIP() net.IP {

	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	if len(interfaces) < 1 {
		return nil
	}

	for i := range interfaces {

		if interfaces[i].Name != "eth0" {
			continue
		}

		ipAddressList, err := interfaces[i].Addrs()

		if err != nil {
			panic(err)
		}

		// Verifying IP is present for the interface
		if len(ipAddressList) < 1 {
			panic("No IP Address for input interface")
		}

		ipAddr, _, ipErr := net.ParseCIDR(ipAddressList[0].String())
		if ipErr != nil {
			panic(ipErr)
		}
		return ipAddr

	}

	ipAddressList, err := interfaces[0].Addrs()

	if err != nil {
		panic(err)
	}

	// Verifying IP is present for the interface
	if len(ipAddressList) < 1 {
		panic("No IP Address for input interface")
	}

	ipAddr, _, ipErr := net.ParseCIDR(ipAddressList[0].String())
	if ipErr != nil {
		panic(ipErr)
	}

	return ipAddr
}

// Get IP address according to the interface passed
func getInterfaceIP(interFace string) net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for i := range interfaces {

		if interfaces[i].Name != interFace {
			continue
		}

		ipAddressList, err := interfaces[i].Addrs()

		if err != nil {
			panic(err)
		}

		// Verifying IP is present for the interface
		if len(ipAddressList) < 1 {
			panic("No IP Address for input interface")
		}

		ipAddr, _, ipErr := net.ParseCIDR(ipAddressList[0].String())
		if ipErr != nil {
			panic(ipErr)
		}
		return ipAddr
	}
	return getDefaultIP()
}

// Chek and return if the interface passed is available else return default interface
func getInterfaceName() string {
	interfaces, err := net.Interfaces()

	if err != nil {
		panic(err)
	}

	if len(interfaces) < 1 {
		errors.New("no interfaces available")
	}

	for i := range interfaces {

		if interfaces[i].Name != *iFlag {
			continue
		}

		return interfaces[i].Name
	}

	return getDefaultInterface()

}

// Returns eth0 or the first interface available
func getDefaultInterface() string {
	interfaces, err := net.Interfaces()

	if err != nil {
		panic(err)
	}

	if len(interfaces) < 1 {
		errors.New("no interfaces available")
	}

	for i := range interfaces {

		if interfaces[i].Name != "eth0" {
			continue
		}

		return interfaces[i].Name
	}

	return interfaces[0].Name

}

