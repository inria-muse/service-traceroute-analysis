from library.path import *
from library.servicetraceroute import *
from library.mypcap import *
from library.plotter import *
from library.paristraceroute import *
from library.zerotrace import *
import os
import json
import argparse
import pickle
import traceback

class Experiment:
    ALGORITHM = 'algorithm'
    DISTANCE = 'distance'
    ITERATIONS = 'iterations'
    INTERPROBE = 'interprobe'
    PROTOCOL = 'protocol'
    SERVICE = 'service'

    def __init__(self, filename, server, verbose=False):
        if verbose:  
            print ("Loading {} from {}".format(filename, server))
        
        splittedFilename = filename.split(".")
        self.verbose = verbose
        self.server = server
        self.conf = {}
        self.packets = None
        self.cleanpackets = None
        self.zerotrace = None
        self.servicetraceroutes = []
        self.cleanservicetraceroutes = []
        self.paristraceroute = []
        self.conf[Experiment.ALGORITHM] = splittedFilename[0][1:]
        
        if self.verbose: 
            print ("\t Algorithm: {}".format(self.conf[Experiment.ALGORITHM]))

        self.conf[Experiment.DISTANCE] = int(splittedFilename[1][1:])
        if self.verbose: 
            print ("\t Distance: {}".format(self.conf[Experiment.DISTANCE]))

        self.conf[Experiment.ITERATIONS] = int(splittedFilename[2][1:])
        if self.verbose: 
            print ("\t Iterations: {}".format(self.conf[Experiment.ITERATIONS]))

        self.conf[Experiment.INTERPROBE] = int(splittedFilename[3][2:])
        if self.verbose: 
            print ("\t Interprobe: {}".format(self.conf[Experiment.INTERPROBE]))

        self.conf[Experiment.PROTOCOL] = splittedFilename[4][1:]
        if self.verbose: 
            print ("\t Protocol: {}".format(self.conf[Experiment.PROTOCOL]))

        self.conf[Experiment.SERVICE] = splittedFilename[5]
        if self.verbose: 
            print ("\t Service: {}".format(self.conf[Experiment.SERVICE]))

        self.iteration = int(splittedFilename[6][3:])
        if self.verbose: 
            print ("\t Server iteration: {}".format(self.iteration))

        self.id = int(splittedFilename[7])
        if self.verbose: 
            print ("\t Experiment id: {}".format(self.id))

    def loadServiceTraceroute(self, filename, clean=False):
        if self.verbose:
            print ("\tLoading {}".format(filename))

        file = open(filename, "r")

        #Parse TraceTCP experiments from the log file
        for line in file:
            #Check that we have the json and not other text
            if line[0] != '{':
                continue

            tracetcp = json.loads(line)

            if clean:
                self.cleanservicetraceroutes.append(TraceTCP(tracetcp))
            else:
                self.servicetraceroutes.append(TraceTCP(tracetcp))

        file.close()
        
        if len(self.servicetraceroutes) <= 0:
            raise Exception("Empty TraceTCP")
        
        if self.verbose:
            print ("\tLoaded {}".format(filename))

    def loadPackets(self, filename):
        self.packets = FastPackets(filename)

    def loadCleanPackets(self, filename):
        self.cleanpackets = FastPackets(filename)

    def loadZerotrace(self, filename):
        self.zerotrace = Zerotrace.LoadZeroTraces(filename, self.verbose)

    def loadParisTraceroutes(self, filename):
        print("Loading paris-traceroute from {}".format(filename))
        f = open(filename)

        pts = json.load(f)

        f.close()

        for key in pts:
            for elem in pts[key]:
                remoteIP = elem['destination']
                remotePort = elem['dstPort']
                localPort = elem['srcPort']
                protocol = elem['protocol']
                algorithm = elem['algorithm']
                tstart = elem['startTimestamp']
                tend = elem['endTimestamp']
                newversion = elem['isNewVersion']
                error = elem['error']

                output = elem['result']
                pt = ParisTraceroute(remoteIP, remotePort, localPort, protocol, algorithm, tstart, tend, newversion, output, error)
                self.paristraceroute.append(pt)
        
        print ("Loaded {}".format(filename))

class Results:
    def __init__(self, verbose=False):
        self.experiments = []
        self.maxDistance = {}
        self.verbose = verbose
        self.banned_server = []
        self.convert_names = {
            'packet':'PacketByPacket',
            'train':'HopByHop',
            'all':'Concurrent',
            'packetbypacket':'PacketByPacket',
            'hopbyhop':'HopByHop',
            'concurrent':'Concurrent'
        }

    def toFiles(self, directory):
        #get servers
        print("Storing all data to {}".format(directory))
        servers = {} 
        for exp in self.experiments:
            if exp.server not in servers:
                servers[exp.server] = []
            servers[exp.server].append(exp)

        for key in servers:
            data = pickle.dumps(servers[key])
            f = open("{}/{}.backup".format(directory, key),"wb")
            f.write(data)
            f.close()
        print("Done!")

    def toFile(self, filename, experiments):
        #get servers
        print("Storing {} experiments to {}".format(len(experiments), filename))
        
        data = pickle.dumps(experiments)
        f = open(filename,"wb")
        f.write(data)
        f.close()
        print("Done!")

    def loadFiles(self, directory, services):
        all_services = ["webpages", "youtube", "twitch"]
        for file in get_files(directory):
            if '.DS_' in file:
                continue
            #check if filename contains the service
            servicetype = get_file(file).split(".")[-2]
            if servicetype in all_services and servicetype not in services:
                continue
            print("Loading data from {}".format(file))
            experiments = pickle.load(open(file, "rb"))
            self.experiments.extend(experiments)
            print("Done!")

    def load(self, init_dir, store_dir, loadLog=True, loadPcap=True, loadParis=True, loadZero=True):
        print ("Loading files from {}".format(init_dir))
        for directory in get_dirs(init_dir):
            experiments = []
            executions = []
            for file in get_files(directory):
                print(file)
                try:
                    expName = get_file_without_2_format(get_file(file))
                except:
                    continue

                #Check if already read
                if expName in executions:
                    continue
                executions.append(expName)
                
                exp = Experiment(expName, get_file(directory), verbose=self.verbose)
                try:
                    if loadLog:
                        exp.loadServiceTraceroute(get_file_without_2_format(file)+".st.log")
                        exp.loadServiceTraceroute(get_file_without_2_format(file)+".stno.log", clean=True)
                    if loadPcap:
                        exp.loadPackets(get_file_without_2_format(file) + ".st.pcap")
                        exp.loadCleanPackets(get_file_without_2_format(file) + ".no.pcap")
                    if loadParis:
                        exp.loadParisTraceroutes(get_file_without_2_format(file) + ".ps.log")
                    if loadZero:
                        exp.loadZerotrace(get_file_without_2_format(file) + ".zt.log")
                    experiments.append(exp)
                except Exception as error:
                    traceback.print_exc()
                    print("Error while reading {}".format(expName))
                    #print(ex.stack_trace)
            self.toFile("{}/{}.webpages.backup".format(store_dir, get_file(directory)), self.getServiceExperiments(experiments, ["webpages"]))
            self.toFile("{}/{}.youtube.backup".format(store_dir, get_file(directory)), self.getServiceExperiments(experiments, ["youtube"]))
            self.toFile("{}/{}.twitch.backup".format(store_dir, get_file(directory)), self.getServiceExperiments(experiments, ["twitch"]))
            # self.experiments.extend(experiments)

    def getServiceExperiments(self, experiments, services):
        array = []
        for exp in experiments:
            if exp.conf[Experiment.SERVICE] in services:
                array.append(exp)
        return array

    def computeMaxDistances(self):
        for exp in self.experiments:
            if exp.server not in self.maxDistance:
                self.maxDistance[exp.server] = {}
            if exp.conf[Experiment.PROTOCOL] not in self.maxDistance[exp.server]:
                self.maxDistance[exp.server][exp.conf[Experiment.PROTOCOL]] = {}
            for trace in exp.servicetraceroutes:
                if trace.remoteIP not in self.maxDistance[exp.server][exp.conf[Experiment.PROTOCOL]]:
                    self.maxDistance[exp.server][exp.conf[Experiment.PROTOCOL]][trace.remoteIP] = trace.lastHop
                else:
                    self.maxDistance[exp.server][exp.conf[Experiment.PROTOCOL]][trace.remoteIP] = max(self.maxDistance[exp.server][exp.conf[Experiment.PROTOCOL]][trace.remoteIP], trace.lastHop)

    def plotPathLength(self, directory, iteration=3, allflows=False, psalgorithm="packetbypacket"):
        if self.verbose:
            print("Computing the path length for {} iterations".format(iteration))
        distance = 32
        #iterations = [1,3]
        interprobes = [5]
        sendingAlgorithm = TraceTCP.TRAIN
        services = ['youtube','twitch', 'webpages']

        for service in services:
            if self.verbose:
                print("\tComputing the path length for service {} with distance {}".format(service, distance))
            sequences = []
            labels = []

            seq_st = []
            seq_st_udp = []
            seq_ps_tcp = []
            seq_ps_udp = []
            seq_ps_icmp = []
            seq_zt = []
            
            for exp in self.experiments:
                for trace in exp.servicetraceroutes:
                    if exp.conf[Experiment.SERVICE] != service or exp.conf[Experiment.ALGORITHM] != sendingAlgorithm or exp.conf[Experiment.ITERATIONS] != iteration:
                        continue
                                
                    if not trace.HasDiscoveredPath() and not allflows:
                        continue
                                
                    #if trace.protocol == "udp":
                    #    seq_st_udp.append(len(Utils.ClearIPs(trace.hops)))
                    #else:
                    seq_st.append(len(Utils.ClearIPs(trace.hops)))

                    for ps in exp.paristraceroute:
                        if trace.remoteIP != ps.targetIP:
                            continue 
                    
                        #Compare
                        if ps.protocol == "tcp":
                            pt_path  = ps.BestPath(trace.hops)
                            seq_ps_tcp.append(len(Utils.ClearIPs(pt_path)))
                        if ps.protocol == "udp" or ps.protocol == "none":
                            seq_ps_udp.append(len(Utils.ClearIPs(ps.SimilarPath(trace.hops))))
                        if ps.protocol == "icmp":
                            seq_ps_icmp.append(len(Utils.ClearIPs(ps.SimilarPath(trace.hops))))

                    if exp.zerotrace:   
                        for zt in exp.zerotrace:
                            if trace.remoteIP != zt.targetIP:
                                continue
                            if zt.hops == []:
                                continue
                            seq_zt.append(len(Utils.ClearIPs(zt.hops)))

            sequences.append(seq_st)
            labels.append("Service T. (TCP)")   
            #if service == "youtube":
            #    sequences.append(seq_st_udp)
            #    labels.append("Service T. (UDP)")     
            
   
            sequences.append(seq_ps_tcp)
            labels.append("Paris T. (TCP)")
            sequences.append(seq_ps_udp)
            labels.append("Paris T. (UDP)")
            sequences.append(seq_ps_icmp)
            labels.append("Paris T. (ICMP)")
            sequences.append(seq_zt)
            labels.append("0Trace")           
                    
            markers = ["v","D","o","^","8","s","p","*","+","x"]
            linestyles = [":","-.","--","-"]
            colors = ["black", "red","navy", "green","purple"]

            if service == "youtube":
                colors = ["black", "red","navy", "green","purple"]
            if self.verbose:
                print("\tPlotting path distance for service {} with distance {}".format(service, distance))

            xmax = 0
            if service == "youtube":
                xmax = 25
            Plotter.MultipleCDF("{}/{}_{}_pathlength_all{}.pdf".format(directory, service, distance, allflows), "Path Length", "Path Length", "CDF", sequences, colors, labels, markers=markers, linestyles=linestyles, xmax=xmax, legenOut=False)

    def plotPathEditDistance(self, directory, iteration=3, allflows=False, psalgorithm="packetbypacket"):
        if self.verbose:
            print("Computing the path edit distance for {} iterations".format(iteration))
        distance = 32
        #iterations = [1,3]
        interprobes = [5]
        sendingAlgorithm = TraceTCP.TRAIN
        services = ['youtube','twitch', 'webpages']

        for service in services:
            if self.verbose:
                print("\tComputing the path edit distance for service {} with distance {}".format(service, distance))
            sequences = []
            labels = []

            seq_ps_tcp = []
            seq_ps_udp = []
            seq_ps_icmp = []
            seq_zt = []
            
            for exp in self.experiments:
                for trace in exp.servicetraceroutes:
                    if exp.conf[Experiment.SERVICE] != service or exp.conf[Experiment.ALGORITHM] != sendingAlgorithm or exp.conf[Experiment.ITERATIONS] != iteration:
                        continue
                                
                    if not trace.HasDiscoveredPath() and not allflows:
                        continue
                                
                    for ps in exp.paristraceroute:
                        if trace.remoteIP != ps.targetIP:
                            continue

                        pt_path = ps.BestPath(trace.hops)
                        empty = True
                        for hop in pt_path:
                            if hop != "":
                                empty = False
                        if empty:
                            continue
                        distance = ps.RealEditDistance(trace.hops)
                        if ps.ContainPathPBP(trace.hops):
                            distance = 0
                        #if distance > 0:
                        #    print(service)
                        #    print("ST: {}".format(trace.hops))
                        #    print("PT: {}".format(pt_path))    
                        #Compare
                        if ps.protocol == "tcp":
                            pt_path = ps.BestPath(trace.hops)
                            distance = ps.RealEditDistance(trace.hops)
                            if ps.ContainPathPBP(trace.hops):
                                distance = 0
                            seq_ps_tcp.append(distance)
                            
                        if ps.protocol == "udp" or ps.protocol == "none":
                            seq_ps_udp.append(ps.RealEditDistance(trace.hops))
                        if ps.protocol == "icmp":
                            seq_ps_icmp.append(ps.RealEditDistance(trace.hops))
                        
                    if exp.zerotrace:
                        for zt in exp.zerotrace:
                            if trace.remoteIP != zt.targetIP:
                                continue
                            seq_zt.append(zt.RealEditDistance(trace.hops))
            sequences.append(seq_ps_tcp)
            labels.append("Paris T. (TCP)")
            sequences.append(seq_ps_udp)
            labels.append("Paris T. (UDP)")
            sequences.append(seq_ps_icmp)
            labels.append("Paris T. (ICMP)")
            sequences.append(seq_zt)
            labels.append("0Trace")
                        
                    
            markers = ["v","D","o","^","8","s","p","*","+","x"]
            linestyles = [":","-.","--","-"]
            colors = ["red","navy", "green","purple"]
            if self.verbose:
                print("\tPlotting path distance for service {} with distance {}".format(service, distance))

            xmax = 0
            if service == "youtube":
                xmax = 15
            Plotter.MultipleCDF("{}/{}_{}_pathdistance_all{}.pdf".format(directory, service, distance, allflows), "Path Edit Distance", "Path Edit Distance", "CDF", sequences, colors, labels, markers=markers, linestyles=linestyles, xmax=xmax)

    def plotAvgThroughput(self, directory, iteration=3, allflows=False):
        if self.verbose:
            print("Computing the average download throughput for {} iterations".format(iteration))
        distance = 32
        #iterations = [1,3]
        interprobes = [5]
        sendingAlgorithm = TraceTCP.TRAIN
        services = ['youtube','twitch', 'webpages']

        sequences = []
        labels = []
        for service in services:
            if self.verbose:
                print("\tComputing the average download throughput for service {} with distance {}".format(service, distance))
            seq = []
            seq_without = []
            seq_udp = []
            seq_udp_without = []
            label = "{}".format(service.capitalize())    
            for exp in self.experiments:
                if exp.conf[Experiment.SERVICE] != service:
                    continue

                analyzed_ports = []

                maxThroughput = -1
                maxUdpThroughput = -1
                maxCleanThroughput = -1
                maxUdpCleanThroughput = -1
                for trace in exp.servicetraceroutes:
                    for key in exp.packets.flows:
                        if trace.remoteIP != exp.packets.flows[key]['remote_ip']:
                            continue
                        if key in analyzed_ports:
                            continue 

                        

                        analyzed_ports.append(key)
                        #If udp --> add to UDP sequences   
                        if exp.conf[Experiment.PROTOCOL] == FastPacket.UDP:
                            avg = 8*exp.packets.flows[key]['down_clean_throughput']
                            maxUdpThroughput = max(maxUdpThroughput, avg)
                            # seq_udp.append(avg)
                            # seq_udp.append(8*exp.packets.flows[key]['down_throughput'])
                            # print("{} - {} ({}) - id {}: remoteIP {} and localPort {} - WITH".format(seq_udp[-1], exp.server, service, exp.id, trace.remoteIP, key))
                            continue
                        #If not UDP and not TCP --> skip!
                        elif exp.conf[Experiment.PROTOCOL] != FastPacket.TCP:
                            continue 
                        avg = 8*exp.packets.flows[key]['down_clean_throughput']
                        maxThroughput = max(maxThroughput, avg)           
                        # seq.append(avg)
                        # seq.append(8*exp.packets.flows[key]['down_throughput'])
                        # print("{} - {} ({}) - id {}: remoteIP {} and localPort {} - WITH".format(seq[-1], exp.server, service, exp.id, trace.remoteIP, key))

                analyzed_ports = []
                for trace in exp.cleanservicetraceroutes:
                    for key in exp.cleanpackets.flows:
                        if trace.remoteIP != exp.cleanpackets.flows[key]['remote_ip']:
                            continue
                        if key in analyzed_ports:
                            continue  
                        
                        analyzed_ports.append(key)
                        #If udp --> add to UDP sequences 
                        if exp.conf[Experiment.PROTOCOL] == FastPacket.UDP:
                            avg = 8*exp.cleanpackets.flows[key]['down_clean_throughput']
                            maxUdpCleanThroughput = max(maxUdpCleanThroughput, avg)
                            # seq_udp_without.append(avg)
                            # print("{} - {} ({}) - id {}: remoteIP {} and localPort {} - WITHOUT".format(seq_udp_without[-1], exp.server, service, exp.id, trace.remoteIP, key))
                            continue
                        #If not UDP and not TCP --> skip!
                        elif exp.conf[Experiment.PROTOCOL] != FastPacket.TCP:
                            continue          
                        avg = 8*exp.cleanpackets.flows[key]['down_clean_throughput'] 
                        maxCleanThroughput = max(maxCleanThroughput, avg) 
                        # seq_without.append(avg)
                        # print("{} - {} ({}) - id {}: remoteIP {} and localPort {} - WITHOUT".format(seq_without[-1], exp.server, service, exp.id, trace.remoteIP, key))
                
                

                if maxCleanThroughput >= 0:
                    seq_without.append(maxCleanThroughput)
                elif maxCleanThroughput>=0:
                    print("WITHOUT Low Throughput of {} for server {} exp {} alg {} service {}".format(maxCleanThroughput, exp.server, exp.id, exp.conf[Experiment.ALGORITHM], exp.conf[Experiment.SERVICE]))
                if maxUdpCleanThroughput >= 0:
                    seq_udp_without.append(maxUdpCleanThroughput)
                elif maxUdpCleanThroughput>=0:
                    print("WITHOUT UDP Low Throughput of {} for server {} exp {} alg {} service {}".format(maxUdpCleanThroughput, exp.server, exp.id, exp.conf[Experiment.ALGORITHM], exp.conf[Experiment.SERVICE]))
                if maxThroughput >= 0:
                    seq.append(maxThroughput)
                elif maxThroughput>=0:
                    print("WITH Low Throughput of {} for server {} exp {} alg {} service {}".format(maxThroughput, exp.server, exp.id, exp.conf[Experiment.ALGORITHM], exp.conf[Experiment.SERVICE]))
                if maxUdpThroughput >= 0:
                    seq_udp.append(maxUdpThroughput)
                elif maxUdpThroughput>=0:
                    print("WITH UDP Low Throughput of {} for server {} exp {} alg {} service {}".format(maxUdpThroughput, exp.server, exp.id, exp.conf[Experiment.ALGORITHM], exp.conf[Experiment.SERVICE]))

            sequences.append([int((f / 1024**1)+.5) for f in seq])
            labels.append(label + " (with)")
            sequences.append([int((f / 1024**1)+.5) for f in seq_without])
            labels.append(label + " (without)")
            if seq_udp != [] and service=="youtube":
                sequences.append([int((f / 1024**1)+.5) for f in seq_udp])
                labels.append(label + " UDP (with)")
                sequences.append([int((f / 1024**1)+.5) for f in seq_udp_without])
                labels.append(label + " UDP (without)")

        markers = ["v","D","o","^","8","s","p","*","+","x"]
        linestyles = [":","-.","--","-"]
        colors = ["red","orange","navy","skyblue", "purple", "orchid","green","lightgreen"]
        if self.verbose:
            print("\tPlotting paverage download throughput for service {} with distance {}".format(service, distance))
        xmax = 60000
        Plotter.MultipleCDF("{}/avgdown_all{}.pdf".format(directory, allflows), "Average Throughput", "Average Throughput [Kb/s]", "CDF", sequences, colors, labels, markers=markers, linestyles=linestyles, binsize=1, xmax=xmax, logscale="x", legenColumn=4, legenOut=False,legenPos="upper left")

    def plotWSize(self, directory, iteration=3, allflows=False):
        if self.verbose:
            print("Computing the TCP window size difference for {} iterations".format(iteration))
        distance = 32
        #iterations = [1,3]
        interprobes = [5]
        sendingAlgorithm = TraceTCP.TRAIN
        services = ['youtube','twitch', 'webpages']

        sequences = []
        labels = []
        for service in services:
            if self.verbose:
                print("\tComputing the TCP window size difference for service {} with distance {}".format(service, distance))
            seq = []
            seq_without = []
            label = "{}".format(service.capitalize())    
            for exp in self.experiments:
                if exp.conf[Experiment.SERVICE] != service:
                    continue
                analyzed_ports = []
                for trace in exp.servicetraceroutes:
                    for key in exp.packets.flows:
                        if trace.remoteIP != exp.packets.flows[key]['remote_ip']:
                            continue
                        if key in analyzed_ports:
                            continue  
                        
                        analyzed_ports.append(key)
                        #If not tcp, skip
                        if exp.packets.flows[key]['protocol'] != FastPacket.TCP:
                            continue            
                        seq.append(exp.packets.flows[key]['wsize'])

                analyzed_ports = []
                for trace in exp.cleanservicetraceroutes:
                    for key in exp.cleanpackets.flows:
                        if trace.remoteIP != exp.cleanpackets.flows[key]['remote_ip']:
                            continue
                        if key in analyzed_ports:
                            continue  
                        
                        analyzed_ports.append(key)
                        #If not tcp, skip
                        if exp.cleanpackets.flows[key]['protocol'] != FastPacket.TCP:
                            continue        
                        seq_without.append(exp.cleanpackets.flows[key]['wsize'])
            sequences.append(seq)
            labels.append(label + " (with)")
            sequences.append(seq_without)
            labels.append(label + " (without)")

        markers = ["v","D","o","^","8","s","p","*","+","x"]
        linestyles = [":","-.","--","-"]
        colors = ["red","orange","navy","skyblue", "purple", "orchid","green","lightgreen"]
        if self.verbose:
            print("\tPlotting window size difference for service {} with distance {}".format(service, distance))
        Plotter.MultipleCDF("{}/wsize_all{}.pdf".format(directory, allflows), "Window Size Difference", "Max Window Size - Min Window Size", "CDF", sequences, colors, labels, markers=markers, linestyles=linestyles, xmax=3000, binsize=1, legenColumn=3, logscale="x", legenOut=False,legenPos="lower right")

    def plotLifetime(self, directory, iteration=3, allflows=False):
        if self.verbose:
            print("Computing the application lifetime for {} iterations".format(iteration))
        distance = 32
        #iterations = [1,3]
        interprobes = [5]
        sendingAlgorithm = TraceTCP.TRAIN
        services = ['youtube','twitch', 'webpages']

        sequences = []
        labels = []
        for service in services:
            if self.verbose:
                print("\tComputing the application lifetime for service {} with distance {}".format(service, distance))
            seq = []
            seq_without = []
            seq_udp = []
            seq_udp_without = []
            label = "{}".format(service.capitalize())    
            for exp in self.experiments:
                if exp.conf[Experiment.SERVICE] != service:
                    continue
                
                analyzed_ports = []
                maxTcp = 0
                maxCleanTcp = 0
                maxUdp = 0
                maxCleanUdp = 0
                for trace in exp.servicetraceroutes:
                    
                    for key in exp.packets.flows:  
                        if trace.remoteIP != exp.packets.flows[key]['remote_ip']:
                            continue
                        
                        if key in analyzed_ports:
                            continue

                        analyzed_ports.append(key)
                        lifetime = abs(exp.packets.flows[key]['lifetime'])
                        #If udp --> add to UDP sequences   
                        if exp.packets.flows[key]['protocol'] == FastPacket.UDP:
                            seq_udp.append(lifetime)
                            maxUdp = max(maxUdp, lifetime)
                            continue
                        #If not UDP and not TCP --> skip!
                        elif exp.packets.flows[key]['protocol'] != FastPacket.TCP:
                            continue            
                        seq.append(lifetime)
                        maxTcp = max(maxTcp, lifetime)

                        if int(lifetime/(10**9)+0.5) > 10 and service == "twitch":
                            print ("lifetime {} for server {} exp {} alg {} service {} and port {}".format(int(lifetime/(10**9)+0.5), exp.server, exp.id, exp.conf[Experiment.ALGORITHM], service, key))
                            print ("Resolution IP: {}".format(trace.resolutionAddr))
                analyzed_ports = []
                for trace in exp.cleanservicetraceroutes:
                    
                    for key in exp.cleanpackets.flows:
                        if trace.remoteIP != exp.cleanpackets.flows[key]['remote_ip']:
                            continue
                        if key in analyzed_ports:
                            continue

                        analyzed_ports.append(key)
                        lifetime = abs(exp.cleanpackets.flows[key]['lifetime'])
                        #If udp --> add to UDP sequences 
                        if exp.cleanpackets.flows[key]['protocol'] == FastPacket.UDP:
                            seq_udp_without.append(lifetime)
                            maxCleanUdp = max(maxCleanUdp, lifetime)
                            continue
                        #If not UDP and not TCP --> skip!
                        elif exp.cleanpackets.flows[key]['protocol'] != FastPacket.TCP:
                            continue            
                        seq_without.append(exp.cleanpackets.flows[key]['lifetime'])
                        maxCleanTcp = max(maxCleanTcp, lifetime)

                # if maxCleanTcp >= 0:
                #     seq_without.append(maxCleanTcp)
                # if maxCleanUdp >= 0:
                #     seq_udp_without.append(maxCleanUdp)
                # if maxTcp >= 0:
                #     seq.append(maxTcp)
                # if maxUdp >= 0:
                #     seq_udp.append(maxUdp)
                
            sequences.append([int(f/(10**9)+0.5) for f in seq])
            labels.append(label + " (with)")
            sequences.append([int(f/(10**9)+0.5) for f in seq_without])
            labels.append(label + " (without)")
            if seq_udp != [] and service == "youtube":
                sequences.append([int(f/(10**9)+0.5) for f in seq_udp])
                labels.append(label + " UDP (with)")
                sequences.append([int(f/(10**9)+0.5) for f in seq_udp_without])
                labels.append(label + " UDP (without)")

            # print(max(seq))
        markers = ["v","D","o","^","8","s","p","*","+","x"]
        linestyles = [":","-.","--","-"]
        colors = ["red","orange","navy","skyblue", "purple", "orchid","green","lightgreen"]
        if self.verbose:
            print("\tPlotting lifetime for service {} with distance {}".format(service, distance))
        Plotter.MultipleCDF("{}/lifetime_all{}.pdf".format(directory, allflows), "Lifetime", "Lifetime [s]", "CDF", sequences, colors, labels, markers=markers, linestyles=linestyles, binsize=10, xmax=300, legenColumn=4, legenOut=False)

    def printPathChanges(self, allflows=False, psalgorithm="packetbypacket"):
        if self.verbose:
            print("Computing the path changes")
        distance = 32
        #iterations = [1,3]
        interprobes = [5]
        sendingAlgorithm = TraceTCP.TRAIN
        services = ['youtube','twitch', 'webpages']

        for service in services:
            if self.verbose:
                print("\tComputing the path changes for service {} with distance {}".format(service, distance))

            total_ps_icmp = 0
            origin_ps_icmp = 0
            middle_ps_icmp = 0
            end_ps_icmp = 0
            as_name_icmp = {}
            as_name_icmp['total'] = 0

            total_ps_tcp = 0
            origin_ps_tcp = 0
            middle_ps_tcp = 0
            end_ps_tcp = 0
            as_name_tcp = {}
            as_name_tcp['origin'] = {}
            as_name_tcp['origin']['total'] = 0
            as_name_tcp['origin']['others'] = {}
            as_name_tcp['origin']['others']['%'] = 0
            as_name_tcp['middle'] = {}
            as_name_tcp['middle']['total'] = 0
            as_name_tcp['middle']['others'] = {}
            as_name_tcp['middle']['others']['%'] = 0
            as_name_tcp['destination'] = {}
            as_name_tcp['destination']['total'] = 0
            as_name_tcp['destination']['others'] = {}
            as_name_tcp['destination']['others']['%'] = 0

            total_ps_udp = 0
            origin_ps_udp = 0
            middle_ps_udp = 0
            end_ps_udp = 0
            as_name_udp = {}
            as_name_udp['total'] = 0

            total_zt = 0
            origin_zt = 0
            middle_zt = 0
            end_zt = 0
            as_name_zt = {}
            
            for exp in self.experiments:
                for trace in exp.servicetraceroutes:
                    if exp.conf[Experiment.SERVICE] != service or exp.conf[Experiment.ALGORITHM] != sendingAlgorithm:
                        continue
                                
                    if not trace.HasDiscoveredPath() and not allflows:
                        continue

                    if trace.service == 'youtube' and 'googlevideo' not in trace.resolutionAddr:
                        continue
                                
                    hops = Utils.ClearIPs(trace.hops)
                    for ps in exp.paristraceroute:
                        if trace.remoteIP != ps.targetIP:
                            continue 
                        if trace.localPort != ps.localPort:
                            continue
                        if ps.algorithm != psalgorithm:
                            continue

                        
                            
                        ps_hops = ps.BestPath(hops)
                        ips = Utils.PathChanges(hops, ps_hops)
                        origAs = Utils.OriginAS(ps_hops)
                        destAs = Utils.AS(trace.remoteIP)
                                

                        origin = False
                        middle = False
                        dest = False

                        if not ps.ContainPath(hops):
                            for ip in ips:
                                if Utils.AS(ip) == origAs:# or Utils.IsPrivateIP(ip):
                                    origin = True
                                elif Utils.AS(ip) == destAs:
                                    dest = True
                                else:
                                    middle = True

                        #Compare
                        if ps.protocol == "tcp":
                            if origin or middle or dest:
                                for ip in ips:
                                    asname = Utils.AS(ip)

                                    location = "middle"
                                    if asname == origAs:# or Utils.IsPrivateIP(ip):
                                       location = "origin"
                                    elif asname == destAs:
                                        location = "destination"

                                    if asname >= 0:
                                        if asname not in as_name_tcp[location]:
                                            as_name_tcp[location][asname] = {}
                                            as_name_tcp[location][asname]['%'] = 0
                                            as_name_tcp[location][asname]['servers'] = []
                                        as_name_tcp[location][asname]['%'] += 1
                                         
                                        if exp.server not in as_name_tcp[location][asname]['servers']:
                                            as_name_tcp[location][asname]['servers'].append(exp.server)
                                    else:
                                        if ip not in as_name_tcp:
                                            as_name_tcp[location][ip] = {}
                                            as_name_tcp[location][ip]['%'] = 0
                                            as_name_tcp[location][ip]['servers'] = []
                                        as_name_tcp[location][ip]['%'] += 1

                                        if exp.server not in as_name_tcp[location][ip]['servers']:
                                            as_name_tcp[location][ip]['servers'].append(exp.server)
                                    
                                     
                            total_ps_tcp += 1
                            if origin:
                                origin_ps_tcp += 1
                            elif middle:
                                middle_ps_tcp += 1
                            elif dest:
                                end_ps_tcp += 1
                        if ps.protocol == "udp" or ps.protocol == "none":
                            if origin or middle or dest:
                                for ip in ips[:1]:
                                    asname = Utils.AS(ip)
                                    if asname >= 0:
                                        if asname not in as_name_udp:
                                            as_name_udp[asname] = 0
                                        as_name_udp[asname] += 1
                                    else:
                                        if ip not in as_name_udp:
                                            as_name_udp[ip] = 0
                                        as_name_udp[ip] += 1
                                    as_name_udp["total"] += 1
                                
                            total_ps_udp += 1
                            if origin:
                                origin_ps_udp += 1
                            elif middle:
                                middle_ps_udp += 1
                            elif dest:
                                end_ps_udp += 1
                        if ps.protocol == "icmp":
                            if origin or middle or dest:
                                for ip in ips[:1]:
                                    asname = Utils.AS(ip)
                                    if asname >= 0:
                                        if asname not in as_name_icmp:
                                            as_name_icmp[asname] = 0
                                        as_name_icmp[asname] += 1
                                    else:
                                        if ip not in as_name_icmp:
                                            as_name_icmp[ip] = 0
                                        as_name_icmp[ip] += 1
                                    as_name_icmp["total"] += 1
                                
                            total_ps_icmp += 1
                            if origin:
                                origin_ps_icmp += 1
                            elif middle:
                                middle_ps_icmp += 1
                            elif dest:
                                end_ps_icmp += 1
                        
                    if exp.zerotrace:
                        for zt in exp.zerotrace:
                            if trace.remoteIP != zt.targetIP:
                                continue
                            if zt.hops == []:
                                continue
                            
                            zt_hops = zt.hops
                            ips = Utils.PathChanges(hops, zt_hops)
                            origAs = Utils.OriginAS(zt_hops)
                            destAs = Utils.AS(trace.remoteIP)
                                    
                            origin = False
                            middle = False
                            dest = False

                            for ip in ips:
                                if Utils.AS(ip) == origAs:
                                    origin = True
                                elif Utils.AS(ip) == destAs:
                                    dest = True
                                else:
                                    middle = True

                            total_zt += 1
                            if origin:
                                origin_zt += 1
                            if middle:
                                middle_zt += 1
                            if dest:
                                end_zt += 1

            total_ps_icmp = max(total_ps_icmp, 1)
            total_ps_tcp = max(total_ps_tcp, 1)
            total_ps_udp = max(total_ps_udp, 1)
            total_zt = max(total_zt, 1)

            for loc in as_name_tcp:
                as_name_tcp[loc]['total'] = 0
                for key in as_name_tcp[loc]:
                    if key == "total" or key == "others":
                        continue
                    as_name_tcp[loc]['total'] += as_name_tcp[loc][key]['%']

            keys_to_delete = []
            for loc in as_name_tcp:
                for key in as_name_tcp[loc]:
                    if key == "total" or key == "others":
                        continue
                    as_name_tcp[loc][key]['%'] = float(as_name_tcp[loc][key]['%'])*100.0 / as_name_tcp[loc]['total']

                    if as_name_tcp[loc][key]['%'] < 1.0:
                        as_name_tcp[loc]['others']['%'] += as_name_tcp[loc][key]['%']
                        keys_to_delete.append(key)

                    as_name_tcp[loc][key]['%'] = round(as_name_tcp[loc][key]['%'],2)
            

            for loc in as_name_tcp:
                as_name_tcp[loc]['others']['%'] = round(as_name_tcp[loc]['others']['%'],2)
                for key in keys_to_delete:
                    if key in as_name_tcp[loc]:
                        del as_name_tcp[loc][key]
            keys_to_delete = []

            for key in as_name_udp:
                if key == "total":
                    continue
                as_name_udp[key] = round(float(as_name_udp[key])*100.0 / as_name_udp['total'], 2)

                if as_name_udp[key] < 1.0:
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                del as_name_udp[key]
            keys_to_delete = []

            for key in as_name_icmp:
                if key == "total":
                    continue
                as_name_icmp[key] = round(float(as_name_icmp[key])*100.0 / as_name_icmp['total'], 2)

                if as_name_icmp[key] < 1.0:
                    keys_to_delete.append(key)
            
            for key in keys_to_delete:
                del as_name_icmp[key]
            keys_to_delete = []
            print ("######## PATH CHANGES ({}) ########".format(service))
            print ("Paris Traceroute TCP")
            print ("\tOrigin: {} [{}/{}]".format(round(origin_ps_tcp/total_ps_tcp, 2), origin_ps_tcp, total_ps_tcp))
            print ("\tMiddle: {} [{}/{}]".format(round(middle_ps_tcp/total_ps_tcp, 2), middle_ps_tcp, total_ps_tcp))
            print ("\tDestination: {} [{}/{}]".format(round(end_ps_tcp/total_ps_tcp, 2), end_ps_tcp, total_ps_tcp))
            print ("\tAS with changes: {}".format(as_name_tcp))
            print ("\n")
            print ("Paris Traceroute UDP")
            print ("\tOrigin: {} [{}/{}]".format(round(origin_ps_udp/total_ps_udp, 2), origin_ps_udp, total_ps_udp))
            print ("\tMiddle: {} [{}/{}]".format(round(middle_ps_udp/total_ps_udp, 2), middle_ps_udp, total_ps_udp))
            print ("\tDestination: {} [{}/{}]".format(round(end_ps_udp/total_ps_udp, 2), end_ps_udp, total_ps_udp))
            print ("\tAS with changes: {}".format(as_name_udp))
            print ("\n")
            print ("Paris Traceroute ICMP")
            print ("\tOrigin: {} [{}/{}]".format(round(origin_ps_icmp/total_ps_icmp, 2), origin_ps_icmp, total_ps_icmp))
            print ("\tMiddle: {} [{}/{}]".format(round(middle_ps_icmp/total_ps_icmp, 2), middle_ps_icmp, total_ps_icmp))
            print ("\tDestination: {} [{}/{}]".format(round(end_ps_icmp/total_ps_icmp, 2), end_ps_icmp, total_ps_icmp))
            print ("\tAS with changes: {}".format(as_name_icmp))
            print ("\n")
            print ("0Trace")
            if total_zt == 0:
                print("All 0")
                continue
            print ("\tOrigin: {} [{}/{}]".format(round(origin_zt/total_zt, 2), origin_zt, total_zt))
            print ("\tMiddle: {} [{}/{}]".format(round(middle_zt/total_zt, 2), middle_zt, total_zt))
            print ("\tDestination: {} [{}/{}]".format(round(end_zt/total_zt, 2), end_zt, total_zt))    

    def plotRetransmissions(self, directory, iteration=3, allflows=False):
        '''
        youtube servers giving problems with ST:
        - 74.125.110.7
        - 
        '''
        if self.verbose:
            print("Computing the TCP retransmissions for {} iterations".format(iteration))
        distance = 32
        #iterations = [1,3]
        interprobes = [5]
        sendingAlgorithm = TraceTCP.TRAIN
        services = ['youtube','twitch', 'webpages']

        sequences = []
        labels = []
        for service in services:
            if self.verbose:
                print("\tComputing the TCP retransmissions for service {} with distance {}".format(service, distance))
            seq = []
            seq_without = []
            label = "{}".format(service.capitalize())    
            for exp in self.experiments:
                if exp.conf[Experiment.SERVICE] != service:
                    continue
                
                analyzed_ports = []
                for trace in exp.servicetraceroutes:
                    for key in exp.packets.flows:
                        if trace.remoteIP != exp.packets.flows[key]['remote_ip']:
                            continue
                        if key in analyzed_ports:
                            continue
                    

                        analyzed_ports.append(key)
                        #If not tcp, skip
                        if exp.packets.flows[key]['protocol'] != FastPacket.TCP:
                            continue            
                        retr = exp.packets.flows[key]['retransmissions']
                        seq.append(retr)

                        if retr > 50:
                            print ("{} retransmissions for server {} exp {} alg {} service {} and port {}".format(retr, exp.server, exp.id, exp.conf[Experiment.ALGORITHM], service, key))
                analyzed_ports = []
                for trace in exp.cleanservicetraceroutes:
                    for key in exp.cleanpackets.flows:
                        if trace.remoteIP != exp.cleanpackets.flows[key]['remote_ip']:
                            continue
                        if key in analyzed_ports:
                            continue
                        
                        analyzed_ports.append(key)
                        #If not tcp, skip
                        if exp.cleanpackets.flows[key]['protocol'] != FastPacket.TCP:
                            continue        
                        seq_without.append(exp.cleanpackets.flows[key]['retransmissions'])
            sequences.append(seq)
            labels.append(label + " (with)")
            sequences.append(seq_without)
            labels.append(label + " (without)")

        markers = ["v","D","o","^","8","s","p","*","+","x"]
        linestyles = [":","-.","--","-"]
        colors = ["red","orange","navy","skyblue", "purple", "orchid","green","lightgreen"]
        if self.verbose:
            print("\tPlotting retransmissions for service {} with distance {}".format(service, distance))
        Plotter.MultipleCDF("{}/retransmissions_all{}.pdf".format(directory, allflows), "TCP Retransmissions", "Number of retransmissions", "CDF", sequences, colors, labels, markers=markers, linestyles=linestyles, xmax=15, binsize=1, legenOut=False,legenPos="lower right", legenColumn=3)

    def plotResets(self, directory, iteration=3, allflows=False):
        if self.verbose:
            print("Computing the TCP resets for {} iterations".format(iteration))
        distance = 32
        #iterations = [1,3]
        interprobes = [5]
        sendingAlgorithm = TraceTCP.TRAIN
        services = ['youtube','twitch', 'webpages']

        sequences = []
        labels = []
        for service in services:
            if self.verbose:
                print("\tComputing the TCP resets for service {} with distance {}".format(service, distance))
            seq = []
            seq_without = []
            label = "{}".format(service)    
            for exp in self.experiments:
                if exp.conf[Experiment.SERVICE] != service:
                    continue
                rsts_with = 0
                rsts_without = 0
                for key in exp.packets.flows:  
                    #If not tcp, skip
                    if exp.packets.flows[key]['protocol'] != FastPacket.TCP:
                        continue            
                    if exp.packets.flows[key]['closed_by'] == FastPacket.RST:
                        rsts_with += 1
                    #     print ("Closed by RST")
                    # elif exp.packets.flows[key]['closed_by'] == FastPacket.FIN:
                    #     print ("Closed by FIN")
                    # else:
                    #     print ("Closed by None")
                seq.append(rsts_with)
                for key in exp.cleanpackets.flows:
                    #If not tcp, skip
                    if exp.cleanpackets.flows[key]['protocol'] != FastPacket.TCP:
                        continue    
                    if exp.cleanpackets.flows[key]['closed_by'] == FastPacket.RST:
                        rsts_without += 1
                    #     print ("Closed by RST")
                    # elif exp.cleanpackets.flows[key]['closed_by'] == FastPacket.FIN:
                    #     print ("Closed by FIN")
                    #     pass 
                    # else:
                    #     print ("Closed by None")
                        
                    
                seq_without.append(rsts_without)
            sequences.append(seq)
            labels.append(label + " (with)")
            sequences.append(seq_without)
            labels.append(label + " (without)")

        markers = ["v","D","o","^","8","s","p","*","+","x"]
        linestyles = [":","-.","--","-"]
        colors = ["red","orange","navy","skyblue", "purple", "orchid","green","lightgreen"]
        if self.verbose:
            print("\tPlotting resets for service {} with distance {}".format(service, distance))
        Plotter.MultipleCDF("{}/resets_all{}.png".format(directory, allflows), "TCP Resets", "Number of resets per session", "CDF", sequences, colors, labels, markers=markers, linestyles=linestyles)


    def plotPathLengthRatio(self, directory):
        if self.verbose:
            print("Computing the distance path ratio")
        self.computeMaxDistances()
        distances = [32]
        #iterations = [1,3]
        iterations = [2,4,5,6,7,8,9]
        interprobes = [5]
        sendingAlgorithm = [TraceTCP.PACKET, TraceTCP.TRAIN, TraceTCP.ALL]
        services = ['youtube','twitch', 'webpages']
        for service in services:
            for distance in distances:
                if self.verbose:
                    print("\tComputing the distance path ratio for service {} with distance {}".format(service, distance))
                sequences = []
                labels = []
                for alg in sendingAlgorithm:
                    for it in iterations:
                        seq = []
                        label = "{} [{}]".format(alg, it)       
                        for exp in self.experiments:
                            if exp.server in self.banned_server:
                                continue
                            if exp.conf[Experiment.SERVICE] != service or exp.conf[Experiment.ALGORITHM] != alg or exp.conf[Experiment.DISTANCE] != distance or exp.conf[Experiment.ITERATIONS] != it:
                                continue
                            for trace in exp.servicetraceroutes:
                                if trace.lastHop != 0:
                                    # print ("D{} S{}: {} / {}".format(distance, service, trace.lastHop, self.maxDistance[exp.server][exp.conf[Experiment.PROTOCOL]][trace.remoteIP]))
                                    seq.append(int(100.0*float(trace.lastHop) / float(self.maxDistance[exp.server][exp.conf[Experiment.PROTOCOL]][trace.remoteIP])))
                                else:
                                    seq.append(0)
                        sequences.append(seq)
                        labels.append(label)
                    
                    markers = ["v","D","o","^","8","s","p","*","+","x"]
                    linestyles = [":","-.","--","-"]
                    colors = ["red","orange","navy","skyblue", "green","orchid"]
                    binsize = 5
                if self.verbose:
                    print("\tPlotting distance path ratio for service {} with distance {}".format(service, distance))
                Plotter.MultipleCDF("{}/{}_{}_pathlengthratio.png".format(directory, service, distance), "Path Distance Ratio [distance={}]".format(distance), "Ratio", "CDF", sequences, colors, labels, markers=markers, linestyles=linestyles, binsize=binsize)
                # Plotter.MultipleCDF("{}/{}_{}_it_{}.png".format(directory, distance, inter, field), titles[field].format(distance, inter), xlabel[field], "CDF", sequences_it, colors, labels_it, markers=markers, linestyles=linestyles, binsize=binsize[field], xmax=xmax[field], legenPos=legenpos[field])

    def plotHopRatio(self, directory):
        if self.verbose:
            print("Computing the hop ratio")
        distances = [32]
        iterations = [1,2,3,4,5,6,7,8,9]
        interprobes = [5]
        sendingAlgorithm = [TraceTCP.PACKET, TraceTCP.TRAIN, TraceTCP.ALL]
        services = ['youtube','twitch', 'webpages']

        for service in services:
            for distance in distances:
                if self.verbose:
                    print("\tComputing the hop ratio for service {} with distance {}".format(service, distance))
                avgs = []
                stds = []
                labels = []
                for alg in sendingAlgorithm:
                    label = "{}".format(alg)
                    seqAvg = []  
                    seqStd = []  
                    for it in iterations: 
                        seq = []
                        for exp in self.experiments:
                            if exp.server in self.banned_server:
                                continue
                            if exp.conf[Experiment.SERVICE] != service or exp.conf[Experiment.ALGORITHM] != alg or exp.conf[Experiment.DISTANCE] != distance or exp.conf[Experiment.ITERATIONS] != it:
                                continue
                            #Get how many diff hops there are between paristraceroute and servicetraceroute
                            for trace in exp.servicetraceroutes:
                                if (service == "youtube" or service == "twitch") and trace.flowEnded:
                                    continue
                                mod = False
                                for ps in exp.paristraceroute:
                                    if mod:
                                        continue
                                    if trace.remoteIP != ps.targetIP:
                                        continue
                                    #Compare
                                    seq.append(ps.RealEditDistance(trace.hops))
                                    mod = True

                        stats = Stats(seq)
                        seqAvg.append(stats.Avg())
                        seqStd.append(stats.StandardDeviation())
                        # if self.verbose:
                        #     print("\tAvg {} - Std {}".format(stats.Avg(), stats.StandardDeviation()))
                    avgs.append(seqAvg)
                    stds.append([f/2 for f in seqStd])
                    labels.append(label)
                    
                markers = ["v","D","o","^","8","s","p","*","+","x"]
                linestyles = [":","-.","--","-"]
                colors = ["red","orange","navy","skyblue", "green","orchid"]
                    
                if self.verbose:
                    print("\tPlotting the probe throughput for service {} with distance {}".format(service, distance))
                Plotter.MultiErrorXY("{}/{}_{}_hopratio_error.png".format(directory, service, distance), "Edit Distance", "#Probes per Hop", "Avg Edit Distance", 0, 0, iterations, avgs, stds, colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                Plotter.MultiErrorXY("{}/{}_{}_hopratio_noerror.png".format(directory, service, distance), "Edit Distance", "#Probes per Hop", "Avg Edit Distance", 0, 0, iterations, avgs, [None]*len(avgs), colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
   
    def plotFlowEnded(self, directory):
        if self.verbose:
            print("Computing ratio of flow ended")
        distances = [32]
        iterations = [1,2,3,4,5,6,7,8,9]
        interprobes = [5]
        sendingAlgorithm = [TraceTCP.PACKET, TraceTCP.TRAIN, TraceTCP.ALL]
        services = ['youtube','twitch', 'webpages']

        for service in services:
            for distance in distances:
                if self.verbose:
                    print("\tComputing the ratio of flow ended for service {} with distance {}".format(service, distance))
                seqsClosed = []
                seqsReached = []
                seqsTotal = []
                seqsx = []
                avgsClosed = []
                stdsClosed = []
                avgsReached = []
                stdsReached = []
                avgsTotal = []
                stdsTotal = []
                labels = []
                maxy = []
                maxx = []
                maxy1 = []

                seqsRatioX = []
                seqsRatioY = []
                seqsRatioAvg = []
                seqsRatioStd = []
                
                for alg in sendingAlgorithm:
                    label = "{}".format(self.convert_names[alg])
                    seqAvgClosed = []  
                    seqStdClosed = []
                    seqAvgReached = []  
                    seqStdReached = []
                    seqAvgTotal = []
                    seqStdTotal = []
                    scatterFail = []
                    scatterSucc = []
                    scatterFlows = []
                    scatterX = []  

                    totalFlows = {}
                    completedFlows = {}

                    for it in iterations: 
                        seqFail = []
                        seqSucc = []
                        seqTotal = []
                        for exp in self.experiments:
                            if exp.server not in totalFlows:
                                totalFlows[exp.server] = {}
                            if exp.server not in completedFlows:
                                completedFlows[exp.server] = {}
                            if it not in totalFlows[exp.server]:
                                totalFlows[exp.server][it] = 0
                            if it not in completedFlows[exp.server]:
                                completedFlows[exp.server][it] = 0

                            if exp.server in self.banned_server:
                                continue
                            if exp.conf[Experiment.SERVICE] != service or exp.conf[Experiment.ALGORITHM] != alg or exp.conf[Experiment.DISTANCE] != distance or exp.conf[Experiment.ITERATIONS] != it:
                                continue
                            if exp.servicetraceroutes == []:
                                continue
                            

                            failed = 0
                            success = 0
                            totalsum = 0

                            videoIPs = []

                            for key in exp.packets.queries:
                                # if service == "twitch" and "spade" in exp.packets.queries[key]:
                                #     print("Checking DNS query {} - {}".format(key, exp.packets.queries[key]))
                                if "googlevideo" in str(key) or "ttvnw" in str(key) or ("video" in str(key) and "edge" in str(key)):
                                    # print("Adding {} ({})".format(exp.packets.queries[key], key))
                                    videoIPs.append(exp.packets.queries[key])

                            hostdistances = {}
                            for trace in exp.servicetraceroutes:
                                if trace.flowEnded and (len(trace.hops) - len(Utils.ClearIPs(trace.hops))) < 3 and len(trace.hops) < 28:
                                    continue
                                if trace.remoteIP not in hostdistances:
                                    hostdistances[trace.remoteIP] = len(Utils.ClearIPs(trace.hops))
                                hostdistances[trace.remoteIP] = min(len(Utils.ClearIPs(trace.hops)), hostdistances[trace.remoteIP])

                            
                            for trace in exp.servicetraceroutes:
                                # if service == "twitch":
                                #     if len(Utils.ClearIPs(trace.hops)) < 2:
                                #         continue
                                if service == "youtube":
                                    if trace.remoteIP not in videoIPs:
                                        continue
                                # if service == "twitch":
                                #     if trace.remoteIP not in videoIPs:
                                #         continue
                                #     print("{}: {} (alg {}) - video found!".format(exp.server, exp.conf[Experiment.SERVICE], alg))
                                # if trace.protocol == "udp":
                                #     continue
                                #Compare
                                totalsum += 1
                                totalFlows[exp.server][it] += 1
                                # if trace.flowEnded:
                                if trace.flowEnded and (len(trace.hops) - len(Utils.ClearIPs(trace.hops))) < 3 and len(trace.hops) < 28 and trace.remoteIP not in hostdistances:
                                    failed+=1
                                    # print("\tNot completed!")
                                elif trace.flowEnded and trace.remoteIP in distances and (len(Utils.ClearIPs(trace.hops)) < hostdistances[trace.remoteIP]):
                                    failed+=1
                                else:
                                    success += 1
                                    # print("\tCompleted!")
                                    completedFlows[exp.server][it] += 1
                            # seq.append(int(100*(failed / totalsum)))
                            seqFail.append(failed)
                            seqSucc.append(success)
                            seqTotal.append(totalsum)
                            scatterFail.append(failed)
                            scatterSucc.append(success)
                            scatterFlows.append(totalsum)
                            scatterX.append(it)
                            maxy.append(len(exp.servicetraceroutes))
                            maxx.append(it)
                            # maxy1.append(exp.packets.getNumberProbedFlows())
                        
                        statsFail = Stats(seqFail)
                        seqAvgClosed.append(statsFail.Avg())
                        seqStdClosed.append(statsFail.StandardDeviation())

                        statsSucc = Stats(seqSucc)
                        seqAvgReached.append(statsSucc.Avg())
                        seqStdReached.append(statsSucc.StandardDeviation())

                        statsTotal = Stats(seqTotal)
                        seqAvgTotal.append(statsTotal.Avg())
                        seqStdTotal.append(statsTotal.StandardDeviation())
                        # if self.verbose:
                        #     print("It {}, Algo {}, Service {}:\n\tAvg {} - Std {}\n\t{}".format(it, alg, service, statsFail.Avg(), statsFail.StandardDeviation(), seqFail))
                        #     print("It {}, Algo {}, Service {}:\n\tAvg {} - Std {}\n\t{}".format(it, alg, service, statsSucc.Avg(), statsSucc.StandardDeviation(), seqSucc))

                    avgsClosed.append(seqAvgClosed)
                    stdsClosed.append([f for f in seqStdClosed])
                    avgsReached.append(seqAvgReached)
                    stdsReached.append([f for f in seqStdReached])
                    avgsTotal.append(seqAvgTotal)
                    stdsTotal.append([f for f in seqStdTotal])
                    labels.append(label)
                    seqsClosed.append(scatterFail)
                    seqsReached.append(scatterSucc)
                    seqsTotal.append(scatterFlows)
                    seqsx.append(scatterX)


                    ratioX = []
                    ratioY = []
                    ratioStatsAvg = []
                    ratioStatsStd = []
                    for it in iterations:
                        array = []
                        for key in completedFlows:
                            if completedFlows[key][it] == 0:
                                continue
                            ratio = float(completedFlows[key][it]) / float(totalFlows[key][it])
                            if ratio < 0.85:
                                print("Server {} with service {}, iteration {} and algorithm {} has rate of {}".format(key, service, it, alg, ratio))
                            ratioX.append(it)
                            ratioY.append(ratio)
                            array.append(ratio)
                        ratioStats = Stats(array)
                        ratioStatsAvg.append(ratioStats.Avg())
                        ratioStatsStd.append(ratioStats.StandardDeviation())
                    seqsRatioX.append(ratioX)
                    seqsRatioY.append(ratioY)
                    seqsRatioAvg.append(ratioStatsAvg)
                    seqsRatioStd.append(ratioStatsStd)
                    
                    
                # seqs.append(maxy)
                # seqsx.append(maxx)
                # labels.append("Max #Flows")
                # seqs.append(maxy1)
                # seqsx.append(maxx)
                # labels.append("#Opened Flows")
                markers = ["v","D","o","^","8","s","p","*","+","x"]
                linestyles = [":","-.","--","-"]
                colors = ["red","orange","navy","skyblue", "green","orchid"]
                    
                if self.verbose:
                    print("\tPlotting the ratio of flow ended for service {} with distance {}".format(service, distance))
                Plotter.MultiErrorXY("{}/{}_{}_flowended_error.pdf".format(directory, service, distance), "Flows Ended before Service Traceroute", "#Probes per Hop", "#Ended Flows", 0, 0, iterations, avgsClosed, stdsClosed, colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                #Plotter.MultiErrorXY("{}/{}_{}_flowended_noerror.png".format(directory, service, distance), "Flows Ended before Service Traceroute", "#Probes per Hop", "#Ended Flows", 0, 0, iterations, avgs, [None]*len(avgs), colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                Plotter.MultiScatter("{}/{}_{}_flowended_scatter.pdf".format(directory, service, distance), "Flows Ended before Service Traceroute", "#Probes per Hop", "#Ended Flows", seqsx, seqsClosed, colors, labels, markers=markers, legenOut=True)
                
                Plotter.MultiErrorXY("{}/{}_{}_flowreached_error.pdf".format(directory, service, distance), "Flows Ended after Service Traceroute", "#Probes per Hop", "#Flows", 0, 0, iterations, avgsReached, stdsReached, colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                #Plotter.MultiErrorXY("{}/{}_{}_flowended_noerror.png".format(directory, service, distance), "Flows Ended before Service Traceroute", "#Probes per Hop", "#Ended Flows", 0, 0, iterations, avgs, [None]*len(avgs), colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                Plotter.MultiScatter("{}/{}_{}_flowreached_scatter.pdf".format(directory, service, distance), "Flows Ended after Service Traceroute", "#Probes per Hop", "#Flows", seqsx, seqsReached, colors, labels, markers=markers, legenOut=True)

                Plotter.MultiErrorXY("{}/{}_{}_flowtotal_error.pdf".format(directory, service, distance), "Total Number of Flows", "#Probes per Hop", "#Flows", 0, 0, iterations, avgsTotal, stdsTotal, colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                #Plotter.MultiErrorXY("{}/{}_{}_flowended_noerror.png".format(directory, service, distance), "Flows Ended before Service Traceroute", "#Probes per Hop", "#Ended Flows", 0, 0, iterations, avgs, [None]*len(avgs), colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                Plotter.MultiScatter("{}/{}_{}_flowtotal_scatter.pdf".format(directory, service, distance), "Total Number of Flows", "#Probes per Hop", "#Flows", seqsx, seqsTotal, colors, labels, markers=markers, legenOut=True)

                Plotter.MultiErrorXY("{}/{}_{}_flowratio_error.pdf".format(directory, service, distance), "Ratio of Completed Traceroutes", "#Probes per Hop", "Ratio of Completed Traceroutes", 0, 1.1, iterations, seqsRatioAvg, seqsRatioStd, colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                #Plotter.MultiErrorXY("{}/{}_{}_flowended_noerror.png".format(directory, service, distance), "Flows Ended before Service Traceroute", "#Probes per Hop", "#Ended Flows", 0, 0, iterations, avgs, [None]*len(avgs), colors, labels, markers=markers, linestyles=linestyles, legenOut=True)
                Plotter.MultiScatter("{}/{}_{}_flowratio_scatter.pdf".format(directory, service, distance), "Ratio of Completed Traceroutes", "#Probes per Hop", "Ratio of Completed Traceroutes", seqsRatioX, seqsRatioY, colors, labels, markers=markers, legenOut=True)

    def plotAvgProbeThroughput(self, directory, binsize, allflows=False):
        if self.verbose:
            print("Computing the avg probe throughput")
        distances = [32]
        iterations = [1,2,3,4,5,6,7,8,9]
        interprobes = [5]
        sendingAlgorithm = [TraceTCP.PACKET, TraceTCP.TRAIN, TraceTCP.ALL]
        services = ['youtube','twitch', 'webpages']

        for service in services:
            for distance in distances:
                if self.verbose:
                    print("\tComputing the avg probe throughput for service {} with distance {}".format(service, distance))
                avgs = []
                stds = []
                labels = []
                seqs = []
                seqsx = []
                for alg in sendingAlgorithm:
                    label = "{}".format(self.convert_names[alg])
                    seqTCPAvg = []  
                    seqTCPStd = [] 
                    seqUDPAvg = []  
                    seqUDPStd = [] 
                    scatterSeq = []
                    scatterX = []   
                    for it in iterations: 
                        seqTCP = []
                        seqUDP = []
                        for exp in self.experiments:
                            if exp.server in self.banned_server:
                                continue
                            if exp.conf[Experiment.SERVICE] != service or exp.conf[Experiment.ALGORITHM] != alg or exp.conf[Experiment.DISTANCE] != distance or exp.conf[Experiment.ITERATIONS] != it:
                                continue

                            samePorts = {}
                            for trace in exp.servicetraceroutes:
                                if trace.localPort not in samePorts:
                                    samePorts[trace.localPort] = 0
                                else:
                                    samePorts[trace.localPort] += 1

                                if trace.flowEnded and (len(trace.hops) - len(Utils.ClearIPs(trace.hops))) < 3 and len(trace.hops) < 28 and not allflows:
                                    continue

                                #avg = exp.packets.getAvgProbeThroughput(samePorts[trace.localPort], port=trace.localPort)
                                # if len(exp.packets.flows[trace.localPort]['probe_throughput']) < 2:
                                #     continue
                                avg = exp.packets.flows[trace.localPort]['probe_throughput'][samePorts[trace.localPort]]
                                if exp.packets.flows[trace.localPort]['protocol'] == FastPacket.TCP:
                                    seqTCP.append(avg)
                                else:
                                    seqUDP.append(avg)
                                scatterSeq.append(avg)
                                scatterX.append(it)
                                if avg > 1500:
                                    print("Throughput {} for exp {}, service {}, alg {} remoteIP {} and localPort {}".format(avg, exp.id, service, alg, trace.remoteIP, trace.localPort))
                                else:
                                    print("\tThroughput {} for exp {}, service {}, alg {} remoteIP {} and localPort {}".format(avg, exp.id, service, alg, trace.remoteIP, trace.localPort))

                        stats = Stats(seqTCP)
                        seqTCPAvg.append(stats.Avg())
                        seqTCPStd.append(stats.StandardDeviation())

                        
                        statsUDP = Stats(seqUDP)
                        seqUDPAvg.append(statsUDP.Avg())
                        seqUDPStd.append(statsUDP.StandardDeviation())
                       
                        
                        print("Service {}, distance {}, algorithm {}, iteration {}".format(service, distance, alg, it))
                        # if self.verbose:
                        #     print("\tSeq: {}".format(seq))
                        #     print("\tAvg {} - Std {}".format(stats.Avg(), stats.StandardDeviation()))
                    avgs.append(seqTCPAvg)
                    stds.append([f/2 for f in seqTCPStd])
                    seqs.append(scatterSeq)
                    seqsx.append(scatterX)
                    labels.append(label + "(TCP)")

                    if service == "youtube":
                        avgs.append(seqUDPAvg)
                        stds.append([f/2 for f in seqUDPStd])
                        labels.append(label+" (UDP)")

                markers = ["v","D","o","^","8","s","p","*","+","x"]
                linestyles = [":","-.","--","-"]
                colors = ["red","orange","navy","skyblue", "purple", "orchid","green","lightgreen"]
                    
                if self.verbose:
                    print("\tPlotting the probe throughput for service {} with distance {}".format(service, distance))
                log = True
                if service == "webpages":
                    log = True
                Plotter.MultiErrorXY("{}/{}_{}_avgprobeput_error_all{}.pdf".format(directory, service, distance,allflows), "Probes Throughput", "#Probes per Hop", "Avg Probe Throughput [B/s]", 0, 0, iterations, avgs, stds, colors, labels, markers=markers, linestyles=linestyles, legenOut=True, legenColumn=3, log=log)
                Plotter.MultiScatter("{}/{}_{}_avgprobeput_scatter_all{}.pdf".format(directory, service, distance, allflows), "Probes throughput", "#Probes per Hop", "Avg Probe Throughput [B/s]", seqsx, seqs, colors, labels, markers=markers, legenOut=True)

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run ServiceTraceroute with different configurations')

    parser.add_argument('--dir', default="data",
                        help='Path position of results')
    parser.add_argument('--plot', default="plots",
                        help='Path position for plots')
    parser.add_argument('--binsize', default=5,
                        help='Throughput bin size')
    parser.add_argument("--backup", default="backups", help="Directory to store all results")
    parser.add_argument("--save", default=False, help="Save file containing all results")
    # parser.add_argument("--read", default=False, help="Read file containing all results")
    res = parser.parse_args()

    results = Results(verbose=True)

    if res.save:
        results.load(res.dir, res.backup, loadZero=False, loadPcap=False)
        
    print("Loading all data from {}".format(res.backup))
    results.loadFiles(res.backup, ["webpages","youtube","twitch"])
    print("Done!")
        
    matplotlib.rcParams.update({'font.size': 20})
    matplotlib.rc('legend', fontsize=15)    
    # if res.save:
    #     results.toFiles(res.backup)

    #results.plotPathEditDistance(res.plot)
    #results.plotPathLength(res.plot)


    #HERE
    # results.plotPathEditDistance(res.plot, allflows=False)
    # results.plotPathLength(res.plot, allflows=False)

    # results.plotLifetime(res.plot)
    # results.plotRetransmissions(res.plot)
    # results.plotAvgThroughput(res.plot)
    # results.plotWSize(res.plot)
    # results.plotResets(res.plot)


    results.printPathChanges()
    #TOHERE

    # results.plotDistanceRatio(res.plot)
    # results.plotProbeThroughput(res.plot, res.binsize)
    # results.plotProbeThroughput2(res.plot, res.binsize)
    # results.plotProbeThroughput2FlowEnded(res.plot, res.binsize)
    # results.plotHopRatio(res.plot)
    # results.plotHopRatioFlowEndedWithAtLeast1Hop(res.plot)
    # results.plotPathDistance(res.plot)
    # results.plotPathDistanceWithFlowEnded(res.plot)
    
    # results.plotPathLength(res.plot, 3, allflows=False)
    # results.plotPathLength(res.plot, 3, allflows=True)
    # results.plotPathDistance(res.plot, 3, allflows=False)
    # results.plotPathDistance(res.plot, 3, allflows=True)
    # results.plotFlowEnded(res.plot)
    # results.plotAvgProbeThroughput(res.plot, res.binsize, allflows=False)
    # results.plotAvgProbeThroughput(res.plot, res.binsize, allflows=True)
    

    # results.plotPathDistanceAllIterations(res.plot, allflows=False)
    # results.plotPathDistanceAllIterations(res.plot, allflows=True)

    # results.plotPathLengthAllIterations(res.plot, allflows=False)
    # results.plotPathLengthAllIterations(res.plot, allflows=True)