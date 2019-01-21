

class PacketScapy:
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

    def __init__(self, packet):
        self.transportType = Packet.NONE
        self.time = packet.time
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

        if 'IP' not in packet:
            return

        self.transportType = Packet.IP
        self.ttl = packet['IP'].ttl
        self.srcIP = packet['IP'].src
        self.dstIP = packet['IP'].dst
        self.emptyTransportPayload = False

        if 'TCP' in packet:
            self.emptyTransportPayload = len(packet['TCP'].payload) == 0
            self.transportPayloadSize = len(packet['TCP'].payload)
            self.transportType = Packet.TCP
            self.dstPort = packet['TCP'].dport
            self.srcPort = packet['TCP'].sport

            self.window = packet['TCP'].window

            self.seqNumber = packet['TCP'].seq
            self.ackNumber = packet['TCP'].ack

            self.ipPayloadSize = len(packet['TCP'])

            if packet['TCP'].flags & Packet.SYN:
                self.SYN = True
            if packet['TCP'].flags & Packet.ACK:
                self.ACK = True
            if packet['TCP'].flags & Packet.FIN:
                self.FIN = True
            if packet['TCP'].flags & Packet.RST:
                self.RST = True

        if 'UDP' in packet:
            self.emptyTransportPayload = len(packet['UDP'].payload) == 0
            self.transportPayloadSize = len(packet['UDP'].payload)
            self.transportType = Packet.UDP
            self.ipPayloadSize = len(packet['UDP'])
            self.dstPort = packet['UDP'].dport
            self.srcPort = packet['UDP'].sport
            
        if 'ICMP' in packet:
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

class PacketsScapy:
    def __init__(self, filename, verbose = False):
        self.verbose = verbose
        self.flows = {}

        self.loadPackets(filename)

    def loadPackets(self, filename):
        if self.verbose:
            print ("Loading packets from {}".format(filename))

        pcaps = rdpcap(filename)

        if len(pcaps) <= 0:
            raise Exception("Empty TCPDump")

        flows = {}
            
        for packet in pcaps:
            pkt = Packet(packet)

            port = 0
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
            print ("Loaded {}".format(filename))

        self.flows = flows



