# from scapy.all import *
import dpkt
import socket
import time 
from library.mystats import *
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip as ipl, icmp
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from pypacker.layer567 import dns


class Packet:
    NONE = -1
    IP = 0
    TCP = 1
    ICMP = 2
    UDP = 3

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self, eth, timestamp):
        self.transportType = Packet.NONE
        self.time = timestamp
        self.ttl = 0
        self.srcIP = ""
        self.dstIP = ""
        self.ipPayloadSize = 0
        self.transportPayloadSize = 0
        self.dstPort = 0
        self.srcPort = 0

        self.window = 0

        self.seqNumber = 0
        self.ackNumber = 0

        self.ACK = False
        self.SYN = False
        self.RST = False
        self.FIN = False

        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            return

        ip = eth.data

        self.transportType = Packet.IP
        self.ttl = ip.ttl
        self.srcIP = socket.inet_ntoa(ip.src)
        self.dstIP = socket.inet_ntoa(ip.dst)
        self.emptyTransportPayload = False
        self.ipPayloadSize = len(ip.data)

        if ip.p == 6:
            tcp = ip.data
            self.emptyTransportPayload = len(tcp.data) == 0
            self.transportPayloadSize = len(tcp.data)
            self.transportType = Packet.TCP
            self.dstPort = tcp.dport
            self.srcPort = tcp.sport

            self.window = tcp.win

            self.seqNumber = tcp.seq
            self.ackNumber = tcp.ack

            if tcp.flags & Packet.SYN:
                self.SYN = True
            if tcp.flags & Packet.ACK:
                self.ACK = True
            if tcp.flags & Packet.FIN:
                self.FIN = True
            if tcp.flags & Packet.RST:
                self.RST = True

        if ip.p == 17:
            udp = ip.data
            self.emptyTransportPayload = len(udp.data) == 0
            self.transportPayloadSize = len(udp.data)
            self.transportType = Packet.UDP
            self.dstPort = udp.dport
            self.srcPort = udp.sport
            
        if ip.p == 1:
            self.transportType = Packet.ICMP

    def IsParisProbe(self):
        if self.transportType == Packet.TCP and self.ttl < 32 and not self.IsServer() and not self.ACK:
            return True
        return False

    def IsProbe(self):
        if self.transportType == Packet.TCP and self.ttl < 32 and self.ACK and self.IsClient():
            return True
        if self.transportType == Packet.UDP and self.ttl < 32 and self.IsClient():
            return True
        return False
    
    def IsClient(self):
        if self.dstPort == 80 or self.dstPort == 443 or self.dstPort == 4443:
            return True
        return False
    def IsServer(self):
        if self.srcPort == 80 or self.srcPort == 443 or self.srcPort == 4443:
            return True
        return False

class Packets:
    def __init__(self, filename, verbose = False):
        self.verbose = verbose
        self.flows = {}
        self.probes = []
        self.loadPackets(filename)

    def getProbeThroughput(self, binsize):
        if len(self.probes) == 0:
            return []
        startTime = self.probes[0].time

        data = 0
        dataArray = []
        lastInterval = 0 + binsize
        for probe in self.probes:
            while lastInterval < (probe.time - startTime):
                dataArray.append(data)
                data = 0
                lastInterval += binsize
            data += probe.transportPayloadSize
        dataArray.append(data)
        return dataArray

    def loadPackets(self, filename):
        if self.verbose:
            print ("Loading packets from {}".format(filename))

        f = open(filename)
        pcaps = dpkt.pcap.Reader(f)

        flows = {}
        
        for ts, buf in pcaps:
            eth = dpkt.ethernet.Ethernet(buf)
            try:
                pkt = Packet(eth, ts)
            except:
                print ("\tError during reading with file {}".format(filename))
                continue
            port = 0
            if pkt.IsProbe():
                self.probes.append(pkt)
            # if pkt.transportType != self.protocol:
            #     continue
            if pkt.srcPort == 80 or pkt.srcPort == 443 or pkt.srcPort == 4443:
                port = pkt.dstPort
            else:
                port = pkt.srcPort

            if port not in flows:
                flows[port] = []

            flows[port].append(pkt)

        if self.verbose:    
            print ("Loaded {}").format(filename)

        self.flows = flows

class FastPacket:
    NONE = "none"
    IP = "ip"
    TCP = "tcp"
    ICMP = "icmp"
    UDP = "udp"
    DNS = "dns"

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self, buf, timestamp):
        eth = ethernet.Ethernet(buf)
        self.transportType = FastPacket.NONE
        self.time = timestamp
        self.ttl = 0
        self.srcIP = ""
        self.dstIP = ""
        self.ipPayloadSize = 0
        self.transportPayloadSize = 0
        self.dstPort = 0
        self.srcPort = 0

        self.window = 0

        self.seqNumber = 0
        self.ackNumber = 0

        self.ACK = False
        self.SYN = False
        self.RST = False
        self.FIN = False

        self.queries = None

        self.packetSize = 0

        if eth[ipl.IP] is None:
            return

        ipL = eth[ipl.IP]

        self.packetSize = len(ipL)

        self.transportType = FastPacket.IP
        self.ttl = ipL.ttl
        self.srcIP = socket.inet_ntoa(ipL.src)
        self.dstIP = socket.inet_ntoa(ipL.dst)
        self.emptyTransportPayload = False

        if ipL[tcp.TCP] is not None:
            tcpL = ipL[tcp.TCP]
            
            self.transportPayloadSize = len(tcpL) - tcpL.hlen
            self.emptyTransportPayload = self.transportPayloadSize == 0
            
            self.transportType = FastPacket.TCP
            self.dstPort = tcpL.dport
            self.srcPort = tcpL.sport
            self.ipPayloadSize = len(tcpL)
            self.window = tcpL.win

            self.seqNumber = tcpL.seq
            self.ackNumber = tcpL.ack

            if tcpL.flags & FastPacket.SYN:
                self.SYN = True
            if tcpL.flags & FastPacket.ACK:
                self.ACK = True
            if tcpL.flags & FastPacket.FIN:
                self.FIN = True
            if tcpL.flags & FastPacket.RST:
                self.RST = True

        if ipL[udp.UDP] is not None:
            udpL = ipL[udp.UDP]
            
            self.transportPayloadSize = len(udpL) - 8
            self.emptyTransportPayload = self.transportPayloadSize == 0
            self.ipPayloadSize = len(udpL)
            self.transportType = FastPacket.UDP
            self.dstPort = udpL.dport
            self.srcPort = udpL.sport

            if udpL[dns.DNS] is not None:
                self.queries = []
                dnsL = udpL[dns.DNS]
                self.transportType = FastPacket.DNS

                if len(dnsL.answers) > 0:
                    if len(dnsL.queries) > 1:
                        print("Yes!")
                        exit(0)
                    for response in dnsL.answers:
                        if response.type != 1:
                            continue
                        try:
                            name = dnsL.queries[0].name
                            ip = socket.inet_ntoa(response.address)
                            self.queries.append((name, ip))
                            
                        except:
                            print("ERROR parsing the dns response addr")
                            print("Length: {} & {}".format(len(dnsL.answers), len(dnsL.queries)))
                            print(dnsL.answers)
                            print(dnsL.queries)
                            #exit(0)
                
            
        if ipL[icmp.ICMP]:
            self.transportType = FastPacket.ICMP

    def IsParisProbe(self):
        if self.transportType == FastPacket.TCP and self.ttl < 32 and not self.IsServer() and not self.ACK:
            return True
        return False

    def IsProbe(self):
        if self.transportType == FastPacket.TCP and self.ttl < 32 and self.ACK and self.IsClient() and self.emptyTransportPayload:
            return True
        if self.transportType == FastPacket.UDP and self.ttl < 32 and self.IsClient() and self.emptyTransportPayload:
            return True
        return False
    
    def IsClient(self):
        if self.dstPort == 80 or self.dstPort == 443 or self.dstPort == 4443:
            return True
        return False

    def IsServer(self):
        if self.srcPort == 80 or self.srcPort == 443 or self.srcPort == 4443:
            return True
        return False

class FastPackets:
    def __init__(self, filename, verbose = False):
        self.verbose = verbose
        self.flows = {}
        self.queries = {}
       
        self.loadPackets(filename)
    

    def getDownlinkPacketsFromFlow(self, flows, srcPort):
        if srcPort not in flows:
            return []
        if flows[srcPort] == []:
            return []

        array = []
        for packet in flows[srcPort]:
            if packet.IsProbe() or packet.IsClient():
                continue
            array.append(packet)
        return array
            
    def getUplinkPacketsFromFlow(self, flows, srcPort):
        if srcPort not in flows:
            return []
        if flows[srcPort] == []:
            return []

        array = []
        for packet in flows[srcPort]:
            if packet.IsProbe() or packet.IsServer():
                continue
            array.append(packet)
        return array

    def getProbesFromFlow(self,flows, srcPort, nrExp):
        if srcPort not in flows:
            return []
        if flows[srcPort] == []:
            return []

        array = []
        lastts = -1
        prevTTL =  -1
        actualExp = 1
        
        for probe in flows[srcPort]:
            if not probe.IsProbe():
                continue
            time = probe.time / (10**9)

            if lastts < 0 or prevTTL < 0:
                lastts = time
                prevTTL = probe.ttl
            
            # print("Previous TS {} (TTL {}) - Actual TS {} (TTL {}) = {} > 60 ?".format(lastts, prevTTL, time, probe.ttl, abs(time-lastts)))
            if abs(time - lastts) > 180 and prevTTL >= probe.ttl:
                actualExp+=1
            # print("\tExp number {} (requested {})".format(actualExp, nrExp))

            lastts = time
            prevTTL = probe.ttl

            if actualExp != nrExp:
                continue
            
            array.append(probe)
        # print("Final array size: {}".format(len(array)))
        return array

    def getProtocol(self, port):
        if port not in self.flows:
            return None
        return self.flows[port]['protocol']

    def getAvgThroughputWithoutIdleTime(self, packets):
        self.verbose = False

        # probes = self.getProbesFromFlow(flows, port, nrExp)

        if self.verbose:
            print("Computing probe throughput")
        if len(packets) <= 1:
            return 0

        maxTime = packets[0].time
        minTime = packets[0].time

        idleTime = 0
        ignorePackets = []

        lastTime = packets[0].time
        for i in range(len(packets)):
            pkt = packets[i]

            maxTime = max(maxTime, pkt.time)
            minTime = min(minTime, pkt.time)

            if (pkt.time / 10**9) - (lastTime / 10**9) > 1.0: #seconds
                idleTime += (pkt.time - lastTime)
                ignorePackets.append(i)

            lastTime = pkt.time

        diff = maxTime - minTime - idleTime

        if diff == 0.0:
            return 0

        diff /= 10**9
        
        data = 0

        # if len(packets) < len(ignorePackets) < 2:
        #     return 0

        for i in range(len(packets)):
            pkt = packets[i]
            if i in ignorePackets:
                continue
            data += pkt.packetSize
            #data += pkt.ipPayloadSize
        return int(data / diff)

    def getAvgThroughput(self, packets):
        self.verbose = False

        # probes = self.getProbesFromFlow(flows, port, nrExp)

        if self.verbose:
            print("Computing probe throughput")
        if len(packets) <= 1:
            return 0

        maxTime = packets[0].time
        minTime = packets[0].time
        for pkt in packets:
            maxTime = max(maxTime, pkt.time)
            minTime = min(minTime, pkt.time)

        maxTime = maxTime / 10**9
        minTime = minTime / 10**9
        diff = maxTime - minTime
        
        data = 0

        for pkt in packets:
            data += pkt.packetSize
            #data += pkt.ipPayloadSize
        return int(data / diff)

    def getNumberApplicationFlows(self, flows, ports=[80,443,4443]):
        total = 0
        for key in flows:
            if flows[key][0].srcPort in ports or flows[key][0].dstPort in ports:
                total+=1
            continue
        return total

    def getLifetime(self, flows, port):
        if port not in flows:
            return 0
        if flows[port] == []:
            return 0

        starTime = flows[port][0].time
        endTime = flows[port][0].time

        ended = False

        for pkt in flows[port]:
            if pkt.IsServer() and pkt.SYN:
                starTime = pkt.time
            if pkt.FIN or pkt.RST:
                endTime = pkt.time
                ended = True
            if not ended and not pkt.IsServer():
                endTime = pkt.time
        return endTime-starTime

    def getRetransmissions(self, flows, port):
        if port not in flows:
            return 0
        if flows[port] == []:
            return 0
        if flows[port][0].transportType == FastPacket.UDP:
            return 0
        
        acks = []
        server = []
        retransmissions = 0

        for pkt in flows[port]:
            if pkt.IsServer() or pkt.IsProbe():
                continue
            acks.append(pkt.ackNumber)
            acks.append(pkt.ackNumber-1)
        

        for pkt in flows[port]:
            if pkt.IsClient() or pkt.IsProbe():
                continue
            
            if pkt.SYN or pkt.emptyTransportPayload:
                continue
            
            if pkt.FIN or pkt.RST:
                return retransmissions
                
            if pkt.seqNumber in acks:
                if pkt.seqNumber in server:
                    retransmissions += 1
                else:
                    server.append(pkt.seqNumber)
        return retransmissions

    def getClosingPacket(self, flows, port):
        if port not in flows:
            return None

        started = False
        
        for pkt in flows[port]:
            if pkt.IsClient() or pkt.IsProbe():
                continue
            if pkt.SYN:
                started = True
            if started and pkt.FIN:
                return pkt.FIN
            if started and pkt.RST:
                return pkt.RST
        return None

    def getNumberResets(self, flows, port):
        if port not in flows:
            return 0

        counter = 0
        for pkt in flows[port]:
            if pkt.IsServer() and pkt.RST:
                counter+=1
        return counter

    def getWSize(self, flows, port):
        if port not in flows:
            return 0
        if flows[port] == []:
            return 0
        if flows[port][0].transportType == FastPacket.UDP:
            return 0
        
        minSize = 0
        maxSize = 0

        for pkt in flows[port]:
            if pkt.IsClient() or pkt.IsProbe():
                continue
            if pkt.SYN or pkt.FIN or pkt.RST:
                continue
            if minSize == 0:
                minSize = pkt.window
            if maxSize == 0:
                maxSize = pkt.window
            minSize = min(minSize, pkt.window)
            maxSize = max(maxSize, pkt.window)
        return maxSize - minSize

    def getRemoteAddrAndPort(self, flows, port):
        if port not in flows:
            return (None,None)
        if flows[port] == []:
            return (None,None)

        remaddr = None
        remport = None

        for pkt in flows[port]:
            if pkt.IsServer():
                remaddr = pkt.srcIP
                remport = pkt.srcPort
                return (remaddr, remport)
            if pkt.IsClient():
                remaddr = pkt.dstIP
                remport = pkt.dstPort
                return (remaddr, remport)
        return (remaddr, remport)

    def loadPackets(self, filename):
        if self.verbose:
            print ("Loading packets from {}".format(filename))

        pcaps = ppcap.Reader(filename=filename)

        flows = {}
        
        for ts, buf in pcaps:
            # self.packets.append(buf)
            pkt = FastPacket(buf, ts)

            if pkt.transportType == FastPacket.DNS:
                for pair in pkt.queries:
                    self.queries[pair[0]] = pair[1]
                continue
            if pkt.transportType != FastPacket.TCP and pkt.transportType != FastPacket.UDP:
                continue
            
            port = 0

            # # if pkt.transportType != self.protocol:
            # #     continue
            if pkt.srcPort == 80 or pkt.srcPort == 443 or pkt.srcPort == 4443:
                port = pkt.dstPort
            elif pkt.dstPort == 80 or pkt.dstPort == 443 or pkt.dstPort == 4443:
                port = pkt.srcPort
            else:
                continue

            if port not in flows:
                flows[port] = []

            flows[port].append(pkt)

        #summarize all data
        for port in flows:
            uppackets = self.getUplinkPacketsFromFlow(flows, port)
            downpackets = self.getDownlinkPacketsFromFlow(flows, port)
            pair = self.getRemoteAddrAndPort(flows, port)

            self.flows[port] = {}
            self.flows[port]['remote_ip'] = pair[0]
            self.flows[port]['remote_port'] = pair[1]
            self.flows[port]['protocol'] = flows[port][0].transportType
            self.flows[port]['up_packets'] = len(uppackets)
            self.flows[port]['down_packets'] = len(downpackets)
            self.flows[port]['probe_packets'] = [] 
            self.flows[port]['closed_by'] = self.getClosingPacket(flows, port)
            self.flows[port]['resets'] = self.getNumberResets(flows, port)
            self.flows[port]['lifetime'] = self.getLifetime(flows, port)
            self.flows[port]['retransmissions'] = self.getRetransmissions(flows, port)
            self.flows[port]['wsize'] = self.getWSize(flows, port)
            self.flows[port]['up_throughput'] = self.getAvgThroughput(uppackets)
            self.flows[port]['up_clean_throughput'] = self.getAvgThroughputWithoutIdleTime(uppackets)
            self.flows[port]['down_throughput'] = self.getAvgThroughput(downpackets)
            self.flows[port]['down_clean_throughput'] = self.getAvgThroughputWithoutIdleTime(downpackets)
            self.flows[port]['probe_throughput'] = []

            for i in range(10):
                probes = self.getProbesFromFlow(flows, port, i+1)
                self.flows[port]['probe_throughput'].append(self.getAvgThroughput(probes))
                self.flows[port]['probe_packets'].append(len(probes))

        if self.verbose:    
            print ("Loaded {}".format(filename))

        flows = {}

        pcaps.close()