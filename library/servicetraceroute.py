from library.utils import *

class TraceTCP:
    PACKET = "packetbypacket"
    TRAIN = "hopbyhop"
    ALL = "concurrent"
    def __init__(self, tracetcp):
        self.service = tracetcp['Data']['Service']
        self.resolutionAddr = ''
        if 'IPResolution' in tracetcp['Data']:
            self.resolutionAddr = tracetcp['Data']['IPResolution']
        self.algorithm = tracetcp['Data']['ProbingAlgorithm'].lower()
        self.protocol = tracetcp['Data']['TransportProtocol']
        self.remoteIP = tracetcp['Data']['TargetIP']
        self.remotePort = tracetcp['Data']['TargetPort']
        self.localIP = tracetcp['Data']['LocalIP']
        self.localPort = tracetcp['Data']['LocalPort']
        self.hops = tracetcp['Data']['Hops']
        self.rtts = tracetcp['Data']['RttsAvg']
        self.ips = tracetcp['Data']['HopIPs']
        self.maxDistance = tracetcp['Data']['BorderDistance']
        self.iterations = tracetcp['Data']["Iterations"]
        self.flowEnded = tracetcp['Data']['FlowEnded']
        self.flowTimeout = tracetcp['Data']['ReachedFlowTimeout']
        self.maxMissingHops = tracetcp['Data']['ReachedMaxConsecutiveMissingHops']
        self.lastHop = 0
        self.serverTTL = []
        self.suggestedServerTTL = 0
        self.rsts = 0
        self.oldProbes = 0
        self.differentIPs = 0 #If we have 2 different IPs for one hop, this will be incremented by 1 (2 if there are 3 IPs, ecc..) 
    
        for i in range(len(self.hops)):
            if tracetcp['Data']['Hops'][i] != '':
                self.lastHop = i+1

        for i in range(len(self.hops)):
            ip = tracetcp['Data']['Hops'][i]
            if self.ips[i] == None:
                self.ips[i] = []
            for device in self.ips[i]:
                if ip != device:
                    self.differentIPs += 1
    
    def HasDiscoveredPath(self):
        if not self.flowEnded:
            return True

        if len(Utils.ClearIPs(self.hops)) <= 0:
            return False
        #PacketByPacket and HopByHop have the feature to stop when 3 hops are not replying
        if self.maxMissingHops:
            return True

        #With Concurrent however, we need to check in details
        #If we have at least 3 empty hops (or 28 discovered hops) then it finished on time
        if (len(self.hops) - len(Utils.ClearIPs(self.hops))) > 2:
            return True
        
        if self.lastHop > 28:
            return True
        
        return False
        
    def HasDiscoveredFullPath(self, pss):
        if self.HasDiscoveredPath():
            return True
        #Check if path length is same (+-1) paris traceroute
        for ps in pss:
            if ps.TargetIP != self.remoteIP:
                continue
            
            path = ps.BestPath(self.hops)

            print("Checking PT and ST")
            print("PT: {}".format(path))
            print("ST: {}".format(self.hops))
            
            diff = len(Utils.ClearIPs(path)) - len(Utils.ClearIPs(self.hops))
            print("PT + 1 <= ST ? : {}".format(diff <= 1))
            if diff <= 1: #If negative then ST discovered more hops!
                return True
        return False