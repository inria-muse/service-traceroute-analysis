from netaddr import *
from pcap import *
import pyasn
from scapy.all import *
import time
import argparse
import json
import sys
import random
import traceback
import jsonpickle
import os
import math
import requests
import csv
import subprocess, shlex
#We want to check:
# Comparison of RSTs between WITH and WITHOUT tracetcp
# Tracetcp path vs paris-traceroute
# Windows size differnce of the server before and during/after tracetcp
# Check retransmissions: if sending an ACK with ack X, we receive a packet from the server with seq X (or X - 1)

#TODO:
# - TraceTCP and ParisTraceroute matches
# - TraceTCP cases: count RSTs BEFORE FIN
# - TraceTCP: check how often the path changes (looking to changes in IP from hops)

#Video
#python2 evaluation/analyser.py --dir video --res plots --json video/analyser.json --service video --overwrite yes
#Webpage
#python2 evaluation/analyser.py --dir webpage --res plots --json webpage/analyser.json --service webpage --overwrite yes

LOG_FILE = ""
PCAP_FILE = ""

                
class Experiment:
    def __init__(self, service, protocol=Packet.TCP):
        self.protocol = protocol
        self.filename = ""
        self.curlTrace = ""
        self.curlNoTrace = ""
        self.service = service.lower()
        self.flowTrace = {}
        self.flowNoTrace = {}
        self.lifetimeTrace = []
        self.lifetimeNoTrace = []
        self.ptrace = []
        self.tracetcp = []
        self.status = ""
        self.rsts_trace_before_end = []
        self.rsts_notrace_before_end = []
        self.rsts_trace = []
        self.rsts_notrace = []
        self.oldprobes = []
        self.wsize_trace = []
        self.wsize_notrace = []
        self.windowDifference_trace = []
        self.windowDifference_notrace = []
        self.nretr_trace = []
        self.nretr_notrace = []
        self.tracetcpchanges = []
        self.avg_throughput_trace = []
        self.avg_throughput_notrace = []
        self.samepaths = 0 #% of path from tracetcp corresponding also to paris-traceroute
        self.totalruns = 0

        self.throughput_trace = []
        self.throughput_notrace = []
    
    def GetOriginAS(self):
        if 'youtube' in self.filename or 'netflix' in self.filename:
            return 2200

        servers = [
            {
                'server':"kulcha.mimuw.edu.pl",
                'asn':8890
            },
            #"node2.planetlab.uni-luebeck.de",
            #"onelab2.pl.sophia.inria.fr",
            {
                'server':"planetlab2.informatik.uni-goettingen.de",
                'asn':680
            },
            {
                'server':"planetlab11.net.in.tum.de",
                'asn':12816
            },
            {
                'server':"planetlab13.net.in.tum.de",
                'asn':12816
            },
            {
                'server':"planetvs2.informatik.uni-stuttgart.de",
                'asn':-1
            },
            {
                'server':"ple1.planet-lab.eu",
                'asn':1307
            },
            {
                'server':"ple41.planet-lab.eu",
                'asn':1307
            },
            {
                'server':"ple43.planet-lab.eu",
                'asn':1307
            },
            {
                'server':"ple44.planet-lab.eu",
                'asn':1307
            }
            #"ple2.hpca.ual.es",
            #"puri.mimuw.edu.pl",
        ]

        for server in servers:
            if server['server'] in self.filename:
                return server['asn']

    def CompareService(self, service):
        service = service.lower()
        if service == "all":
            return True
        if service == "video" and self.service == "netflix":
            return True
        if service == "video" and self.service == "youtube":
            return True
        if service == self.service:
            return True
        return False

    def LoadCurl(self, filename):
        f = open(filename)
        for line in f:
            if 'HTTP' in line:
                self.status = line[line.index("HTTP"):].strip().split(" ")[1]
                return       

    def LoadParisTraceroutes(self, filename):
        print "Loading paris-traceroute from {}".format(filename)
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
                self.ptrace.append(pt)
        
        print "Loaded {}".format(filename)

    def LoadTraceTCP(self, filename):
        print "Loading tracetcp from {}".format(filename)
        file = open(filename, "r")

        #Parse TraceTCP experiments from the log file
        for line in file:
            #Check that we have the json and not other text
            if line[0] != '{':
                continue

            tracetcp = json.loads(line)

            self.tracetcp.append(TraceTCP(tracetcp))

        if len(self.tracetcp) <= 0:
            raise Exception("Empty TraceTCP")
        
        print "Loaded {}".format(filename)
        
    def LoadPcapTracetcp(self, filename):
        self.filename = filename
        self.flowTrace = self.ParsePcap(filename)

        for port in self.flowTrace:
            self.rsts_trace.append(self.ComputeRST(self.flowTrace[port]))
            self.rsts_trace_before_end.append(self.ComputeRSTsBeforeStreamEnd(self.flowTrace[port]))
            self.oldprobes.append(self.ComputeOldProbes(self.flowTrace[port]))
            self.wsize_trace.append(self.ComputeWindowSize(self.flowTrace[port]))
            self.nretr_trace.append(self.ComputeRetransmissions(self.flowTrace[port]))
            self.lifetimeTrace.append(self.ComputeLifetime(self.flowTrace[port]))
            self.avg_throughput_trace.append(self.ComputeAverageThroughput(self.flowTrace[port]))

            throughtput = self.ComputeThroughtput(self.flowTrace[port])
            if throughtput != []:
                self.throughput_trace.append(throughtput)

        for windowmap in self.wsize_trace:
            self.windowDifference_trace.append(self.ComputeWindowDifference(windowmap))

    def LoadPcapNoTracetcp(self, filename):
        self.flowNoTrace = self.ParsePcap(filename)

        for port in self.flowNoTrace:
            self.rsts_notrace.append(self.ComputeRST(self.flowNoTrace[port]))
            self.rsts_notrace_before_end.append(self.ComputeRSTsBeforeStreamEnd(self.flowNoTrace[port]))
            self.wsize_notrace.append(self.ComputeWindowSize(self.flowNoTrace[port]))
            self.lifetimeNoTrace.append(self.ComputeLifetime(self.flowNoTrace[port]))
            self.nretr_notrace.append(self.ComputeRetransmissions(self.flowNoTrace[port]))
            self.avg_throughput_notrace.append(self.ComputeAverageThroughput(self.flowNoTrace[port]))

            throughtput = self.ComputeThroughtput(self.flowNoTrace[port])
            if throughtput != []:
                self.throughput_notrace.append(throughtput)
            
        for windowmap in self.wsize_notrace:
            self.windowDifference_notrace.append(self.ComputeWindowDifference(windowmap))
    def ParsePcap(self, filename):
        print "Loading tcpdump from {}".format(filename)
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

            if pkt.IsParisProbe() and port not in flows:
                continue

            if port not in flows:
                flows[port] = []

            flows[port].append(pkt)
            
        print "Loaded {}".format(filename)
        return flows

    # def ClearData(self):
    #     dirty_ips = []
    #     ports_to_remove = []

    #     for port in self.flowTrace:
    #         #If valid tracetcp, skip
    #         if self.CheckValidTracetcp(self.flowTrace[port]):
    #             continue
            
    #         dstip = ""
    #         for pkt in self.flowTrace[port]:
    #             if pkt.IsServer():
    #                 dstip = pkt.srcIP

    #         #Remove tracetcp
    #         for i in range(len(self.tracetcp)):
    #             tracetcp = self.tracetcp[i]
    #             if tracetcp.remoteIP == dstip and tracetcp.remotePort == port:
    #                 self.tracetcp.pop(i)
            
    #         #Remove paris-traceroute
    #         for i in range(len(self.ptrace)):
    #             ptrace = self.ptrace[i]
    #             if ptrace.targetIP == dstip and ptrace.targetPort == port:
    #                 self.ptrace.pop(i)

    #         ports_to_remove.append(port)
        
    #     for port in ports_to_remove:
    #         #Remove flow
    #         self.flowTrace.pop(port, None)
        
    #     self.rsts_trace = []
    #     self.rsts_trace_before_end = []
    #     self.oldprobes = []
    #     self.wsize_trace = []
    #     self.nretr_trace = []
    #     self.lifetimeTrace = []

    #     for port in self.flowTrace:
    #         self.rsts_trace.append(self.ComputeRST(self.flowTrace[port]))
    #         self.rsts_trace_before_end.append(self.ComputeRSTsBeforeStreamEnd(self.flowTrace[port]))
    #         self.oldprobes.append(self.ComputeOldProbes(self.flowTrace[port]))
    #         self.wsize_trace.append(self.ComputeWindowSize(self.flowTrace[port]))
    #         self.nretr_trace.append(self.ComputeRetransmissions(self.flowTrace[port]))
    #         self.lifetimeTrace.append(self.ComputeLifetime(self.flowTrace[port]))

    #     for windowmap in self.wsize_trace:
    #         self.windowDifference_trace.append(self.ComputeWindowDifference(windowmap))
                    

    #Valid tracetcp = tracetcp ended BEFORE the end of the stream
    def CheckValidTracetcp(self, packets):
        started = False
        ended = False

        for packet in packets:
            if packet.IsServer() and packet.SYN:
                started = True
            elif packet.IsServer() and (packet.FIN or packet.RST):
                ended = True
            elif packet.IsProbe() and ended:
                return False
        return True
        
    #Check lifetime of curl with and without tracetcp
    #To understand if flows lasted less or not
    def ComputeLifetime(self, flow):
        start = 0
        end = 0

        if self.protocol == Packet.TCP:
            for packet in flow:
                if packet.IsServer() and packet.SYN:
                    start = packet.time
                if packet.IsServer() and (packet.FIN or packet.RST):
                    end = packet.time
                    break
        else:
            for packet in flow:
                if packet.IsServer() and start == 0:
                    start = packet.time
                if packet.IsServer():
                    end = packet.time

        if end == 0 and start != 0:
            end = flow[-1].time
        if start == 0 and end !=0:
            start = flow[0].time
        return (end-start)
            
    def ComputeRST(self, packets):
        if self.protocol != Packet.TCP:
            return 0
        rsts = 0
        for packet in packets:
            if packet.IsServer() and packet.RST:
                rsts += 1
        return rsts

    def ComputeAverageThroughput(self, packets):
        data = 0
        starttime = 0
        endtime = 0
        counter = 0
        for packet in packets:
            if packet.IsServer():
                if starttime == 0:
                    starttime = packet.time
                endtime = packet.time
                data += packet.ipPayloadSize
                counter += 1
        if counter < 2:
            return 0

        return float(data) / float(endtime - starttime)

    def ComputeThroughtput(self, packets):
        binsize = 1 #seconds
        bins = []
        starttime = 0
        endtime = 0
        counter = 0
        for packet in packets:
            if packet.IsServer():
                if starttime == 0:
                    starttime = packet.time
                index = int((packet.time - starttime) / binsize)
                if len(bins) <= index:
                    bins += [0]*(index - len(bins) + 1)
    
                bins[index] += packet.transportPayloadSize
                endtime = packet.time
                counter += 1

        if len(bins) < 1:
            return []

        bins = [float(data) for data in bins]

        return bins
        
        
    def ComputeOldProbes(self, packets):
        if self.protocol != Packet.TCP:
            return 0
        started = False
        ended = False
        oldprobes = 0

        for packet in packets:
            if packet.IsServer() and packet.SYN:
                started = True
            elif started and (packet.RST or packet.FIN):
                ended = True
            elif ended and packet.IsProbe():
                oldprobes += 1

        return oldprobes

    def ComputeRSTsBeforeStreamEnd(self, packets):
        if self.protocol != Packet.TCP:
            return 0

        started = False
        ended = False
        rsts = 0

        for packet in packets:
            if packet.IsServer() and packet.SYN:
                started = True
            elif started and (packet.FIN or packet.RST):
                if packet.RST and packet.IsServer():
                    return 1
                return 0
        return 0

    def ComputeWindowSize(self, packets):
        if self.protocol != Packet.TCP:
            return {
                'window': [],
                'traceAt': 0
            }
        started = False
        ended = False
        wsize = []
        startat = 0

        for packet in packets:
            if packet.IsProbe():
                started = True
                startat = len(wsize)
            elif packet.IsServer() and packet.transportType == Packet.TCP and not packet.RST and not packet.SYN and not packet.FIN:
                wsize.append(packet.window)

        return {
            'window': wsize,
            'traceAt': startat
        }

    def ComputeWindowDifference(self, windowmap):
        #print windowmap

        minw = sys.maxint
        maxw = 0
        # begmin = 0
        # endmin = 0
        startat = windowmap['traceAt']

        for elem in windowmap['window']:
            minw = min(minw, elem)
            maxw = max(maxw, elem)

        # for i in range(len(windowmap['window'])):
        #     minw = min(minw, windowmap['window'][i])
        #     maxw = max(maxw, windowmap['window'][i])
            # if i < startat:
            #     begmin = windowmap['window'][i]
            # else:
            #     endmin = windowmap['window'][i]

        #print "{} {}".format(minw, maxw)
        if minw > 0 and maxw > 0 and minw < (2**16):
            return maxw - minw
        # if begmin > 0 and endmin > 0:
        #     return begmin - endmin
        return 0

    def ComputeRetransmissions(self, packets):
        if self.protocol != Packet.TCP:
            return 0

        probesAcks = []
        serverPkts = []
        retransmissions = 0

        for packet in packets:
            if not packet.IsServer():
                probesAcks.append(packet.ackNumber)
                probesAcks.append(packet.ackNumber-1)

        for packet in packets:
            if packet.IsServer():
                if packet.seqNumber in probesAcks and not packet.RST and not packet.emptyTransportPayload:
                    if packet.seqNumber not in serverPkts:
                        serverPkts.append(packet.seqNumber)
                    else:
                        retransmissions += 1

        return retransmissions

    def ComputePathDetection(self):
        for tracetcp in self.tracetcp:
            for paris in self.ptrace:
                if tracetcp.remoteIP == paris.targetIP and tracetcp.remotePort == paris.targetPort:
                    self.totalruns += 1

                    if paris.EditDistance(tracetcp.hops) == 0:
                        self.samepaths += 1

    def CompareCurl(self):
        if self.curlNoTrace == "" or self.curlTrace == "":
            return False
        
        ftrace = open(self.curlTrace)
        ftrace_lines = []

        for line in ftrace:
            ftrace_lines.append(line)
        ftrace.close()

        fnotrace = open(self.curlNoTrace)
        fnotrace_lines = []

        for line in fnotrace:
            fnotrace_lines.append(line)
        fnotrace.close()

        if len(ftrace_lines) != len(fnotrace_lines):
            return False

        for i in range(len(ftrace_lines)):
            if ftrace_lines[i] != fnotrace_lines[i]:
                return False
        return True
       
class Experiments:
    def __init__(self, protocol=Packet.TCP):
        self.experiments = []
        self.protocol = protocol

    def Add(self, experiment):
        self.experiments.append(experiment)

    def Load(self, directory, startingIndex=0, max_iterations=100, max_tests=1000):
        filename_format = "{}/{}_{}_{}.{}.{}"
        services = ["youtube","netflix","webpage"]

        print "Starting from index {}".format(startingIndex)

        for service in services:
            for iteration in range(max_iterations):
                for index in range(startingIndex, max_tests):
                    print "Loading iteration {} index {} for {}".format(iteration, index, service)
                    try:
                        print "Opening {}".format(filename_format.format(directory, "tracetcp", service, index, iteration, "log"))
                        tracetcp_log = filename_format.format(directory, "tracetcp", service, index, iteration, "log")
                        print "Opening {}".format(filename_format.format(directory, "paristraceroute", service, index, iteration, "log"))
                        ptrace_log = filename_format.format(directory, "paristraceroute", service, index, iteration, "log")
                        print "Opening {}".format(filename_format.format(directory, "tcpdump", service, index, iteration, "pcap"))
                        tcpdump_log = filename_format.format(directory, "tcpdump", service, index, iteration, "pcap")
                        print "Opening {}".format(filename_format.format(directory, "tcpdump_notrace", service, index, iteration, "pcap"))
                        tcpdump_notrace_log = filename_format.format(directory, "tcpdump_notrace", service, index, iteration, "pcap")

                        exp = Experiment(service, self.protocol)
                        exp.LoadParisTraceroutes(ptrace_log)
                        exp.LoadTraceTCP(tracetcp_log)
                        exp.LoadPcapTracetcp(tcpdump_log)
                        exp.LoadPcapNoTracetcp(tcpdump_notrace_log)
                        #exp.ClearData()

                        if service == "webpage":
                            curl_log = filename_format.format(directory,"curl_trace", service, index, iteration, "log")
                            exp.LoadCurl(curl_log)
                            exp.curlTrace =  curl_log
                            exp.curlNoTrace = filename_format.format(directory,"curl_notrace", service, index, iteration, "log")

                        #exp.ComputePathDetection()

                        self.Add(exp)
                    except IOError:
                        print "File not found, stopping search"
                        break
                    except AssertionError:
                        exit(1)
                    except Scapy_Exception:
                        print "Empty tcpdump"
                        break
                    except Exception, e:
                        traceback.print_exc()
                        if "tracetcp" not in str(e).lower() and 'tcpdump' not in str(e).lower():
                            exit(1)

    def ToFile(self, filename):
        print "Storing experiments to file"
        pickled = jsonpickle.encode(self.experiments)

        file = open(filename,"w")
        file.write(pickled)
        file.close()
    
    def FromFile(self, filename):
        if filename == "":
            return
        print "Restoring experiments from file"
        file = open(filename,)
        pickled = file.read()
        file.close()

        experiments = jsonpickle.decode(pickled)
        self.experiments.extend(experiments)

    def PlotRSTS(self, directory, service):
        print "Plotting resets"
        rsts_trace = []
        rsts_notrace = []

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            if exp.rsts_trace == []:
                continue
            # if max(exp.rsts_trace) > 0:
            #     print "{} has {} rsts".format(exp.filename, max(exp.rsts_trace))
            rsts_trace.extend(exp.rsts_trace)
            rsts_notrace.extend(exp.rsts_notrace)
        
        Plotter.Histogram(directory+"/{}_resets_trace_{}.pdf".format(self.protocol, service), "Resets with TraceTCP", "Number of Resets", "Number of flows", rsts_trace, 1)
        Plotter.Histogram(directory+"/{}_resets_notrace_{}.pdf".format(self.protocol, service), "Resets without TraceTCP", "Number of Resets", "Number of flows", rsts_notrace, 1)

    def PlotTraceTCPPathChanges(self, directory, service):
        print "Plotting number of tracetcp path changes"
        pathchanges = []

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            for tracetcp in exp.tracetcp:
                if tracetcp.differentIPs > 0:
                    print "{} tracetcp to {} changed path {} times".format(exp.filename, tracetcp.remoteIP, tracetcp.differentIPs)
                pathchanges.append(tracetcp.differentIPs)
        
        Plotter.Histogram(directory+"/{}_path_changes_{}.pdf".format(self.protocol, service), "Path changes with TraceTCP", "Number of path changes", "Number of flows", pathchanges, 1)

    def PlotRSTSBeforeStreamEnd(self, directory, service):
        print "Plotting resets to kill the flow"
        rsts_trace = []
        rsts_notrace = []

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            if exp.rsts_trace_before_end == []:
                continue
            if max(exp.rsts_trace_before_end) > 0:
                print "{} has {} rsts before end if the stream".format(exp.filename, max(exp.rsts_trace_before_end))
                print exp.rsts_notrace_before_end
                print "\n\n"
            if exp.rsts_notrace_before_end != []:
                if max(exp.rsts_notrace_before_end) > 0:
                    print "{} has {} rsts before end if the stream".format(exp.filename, max(exp.rsts_notrace_before_end))
                    print exp.rsts_notrace_before_end
                    print "\n\n"
            # if max(exp.rsts_notrace_before_end) > 0:
            #     print "{} (notracetcp) has {} rsts before end if the stream".format(exp.filename, max(exp.rsts_trace_before_end))
            rsts_trace.extend(exp.rsts_trace_before_end)
            rsts_notrace.extend(exp.rsts_notrace_before_end)
        
        Plotter.Histogram(directory+"/{}_resets_trace_before_end_{}.pdf".format(self.protocol, service), "Flow closed by RST (TraceTCP)", "Number of Resets", "Number of flows", rsts_trace, 1)
        Plotter.Histogram(directory+"/{}_resets_notrace_before_end_{}.pdf".format(self.protocol, service), "Flow closed by RST (No TraceTCP)", "Number of Resets", "Number of flows", rsts_notrace, 1)
        
    def PlotFlowsSize(self, directory, service):
        print "Plotting flow sizes"
        flowSizeTrace = []
        flowSizeNoTrace = []

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue

            if len(exp.flowTrace) > 1:
                ports = []
                for k in exp.flowTrace:
                    ports.append(k)
                # print "{} has {} flows ({})".format(exp.filename, len(exp.flowTrace), ports)

            if len(exp.flowNoTrace) > 1:
                ports = []
                for k in exp.flowNoTrace:
                    ports.append(k)
                # print "{} has {} flows (no trace) ({})".format(exp.filename, len(exp.flowNoTrace), ports)

            flowSizeTrace.append(len(exp.flowTrace))
            flowSizeNoTrace.append(len(exp.flowNoTrace))

        colors = ["red","blue"]
        labels = ["Number of flows (+ Pretend Traceroute)","Number of flows (- Pretend Traceroute)"]
        markers = ["+","*"]
        sequences = [flowSizeTrace, flowSizeNoTrace]

        xlabel = "Number of flows per download"
        if exp.CompareService("video"):
            xlabel = "Number of flows per video"

        Plotter.MultipleCDF("{}/{}_flowsize_{}.pdf".format(directory, self.protocol, service), "Number of flows ({})".format(service), xlabel, "CDF", sequences, colors, labels, markers)


        # Plotter.Histogram(directory+"/flowsize_trace_{}.pdf".format(service), "Number of flows per download with TraceTCP", "Number of flows", "Number of downloads", flowSizeTrace, 1)
        # Plotter.Histogram(directory+"/flowsize_notrace_{}.pdf".format(service), "Number of flows per download without TraceTCP", "Number of flows", "Number of donwloads", flowSizeNoTrace, 1)

    def PlotOldProbes(self, directory, service):
        print "Plotting old probes"
        oldprobes = []

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            # if exp.oldprobes != []:
            #     print "{} has {} old probes".format(exp.filename, max(exp.oldprobes))
            oldprobes.extend(exp.oldprobes)
        
        Plotter.Histogram(directory+"/{}_old_probes_{}.pdf".format(self.protocol, service), "Old probes with TraceTCP", "Number of Old probes", "Number of flows", oldprobes, 1)

    def PlotTraceDistance(self, directory, service):
        print "Plotting tracetcp distances"
        distances = []

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            for tracetcp in exp.tracetcp:
                distances.append(tracetcp.lastHop)
            
        Plotter.Histogram(directory+"/{}_tracetcp_distance_{}.pdf".format(self.protocol, service), "Distance using TraceTCP", "Distance of last replying hop", "Number of flows", distances, 1)

    def PrintPathChangePos(self, service):
        print "Computing position of path changes between tracetcp and paris-traceroute"
        distances = []

        runs = [
            {
                'protocol':'none',
                'algorithm':'mda',
                'dstport':0,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'black',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'tcp',
                'algorithm':'mda',
                'dstport':0,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'red',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'tcp',
                'algorithm':'exhaustive',
                'dstport':0,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'blue',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'icmp',
                'algorithm':'exhaustive',
                'dstport':0,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'yellow',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'udp',
                'algorithm':'exhaustive',
                'dstport':0,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'green',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'tcp',
                'algorithm':'hopbyhop',
                'dstport':0,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'darkviolet',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'icmp',
                'algorithm':'hopbyhop',
                'dstport':0,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'orange',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'udp',
                'algorithm':'hopbyhop',
                'dstport':0,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'darkgray',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'tcp',
                'algorithm':'hopbyhop',
                'dstport':80,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'skyblue',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            },
            {
                'protocol':'tcp',
                'algorithm':'hopbyhop',
                'dstport':443,
                'origin':0,
                'middle':0,
                'destination':0,
                'color':'fuchsia',
                'om':0,
                'md':0,
                'od':0,
                'omd':0,
                'total':0,
            }
        ]
        totalpath = 0
        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            # print "Analyzing path changes in {}".format(exp.filename)
            for tracetcp in exp.tracetcp:
                for ptrace in exp.ptrace:
                    if tracetcp.remoteIP != ptrace.targetIP:
                        continue
                    if ptrace.distance <= 0:
                        continue

                    totalpath += 1
                    path = ptrace.BestPath(tracetcp.hops)

                    #print "Does the path match in {} for {} using paris-traceroute with {} {} {}? {}".format(exp.filename, tracetcp.remoteIP, ptrace.protocol, ptrace.algorithm, ptrace.targetPort, match)
                    for run in runs:
                        orig = False
                        mid = False
                        dst = False
                        if ptrace.algorithm.lower() == run['algorithm'] and ptrace.protocol.lower() == run['protocol']:
                            if run['dstport'] != 0 and run['dstport'] != ptrace.targetPort:
                                continue
                            #Origin AS
                            srcAS = exp.GetOriginAS()
                            # try:
                            #     srcAS = Utils.OriginAS(tracetcp.hops)
                            #     if srcAS < 0:
                            #         srcAS = Utils.OriginAS(path)
                            #         if srcAS < 0:
                            #             print "src AS not found"
                            #             print exp.filename
                            #             print tracetcp.hops
                            #             print path
                            #             print "\n\n"
                            #             continue
                            # except:
                            #     print "src AS exception"
                            #     continue
                            
                            #Dest AS
                            try:
                                dstAS = Utils.AS(tracetcp.remoteIP)
                            except:
                                print "dst AS exception"
                                continue
                            previous = True

                            orig = False
                            mid = False
                            dst = False

                            run['total'] += 1
                            #CHECK AS in the middle
                            for i in range(min(len(tracetcp.hops), len(path))):
                                if tracetcp.hops[i] == "" or "None" in path[i] or path[i] == "":
                                    continue
                                if tracetcp.hops[i] == path[i]:
                                    previous = True
                                    continue
                               
                                #Different IPs

                                #If ip is not public --> only origin
                                if not Utils.IsPublic(tracetcp.hops[i]):
                                    # print path
                                    # print tracetcp.hops
                                    # print "origin"
                                    # print "\n\n"
                                    if previous:
                                        run['origin'] += 1
                                        orig = True
                                    continue
                                try:
                                    as_path = Utils.AS(tracetcp.hops[i])
                                    if as_path == -1:
                                        print tracetcp.hops[i]
                                except:
                                    continue

                                # print "{} {} {} {} change path at hop {}: {} - {}".format(exp.filename, ptrace.algorithm, ptrace.protocol, ptrace.targetPort, i, tracetcp.hops[i], path[i])
                                # print "\t{}\n\t{}".format(tracetcp.hops, path)
                                
                                if previous:
                                    # print "Src AS {} - Dst AS {} ({})".format(srcAS, dstAS, tracetcp.remoteIP)
                                    # print "{} {} {} {}".format(exp.filename, ptrace.algorithm, ptrace.protocol, ptrace.targetPort)
                                    # print path
                                    # print tracetcp.hops
                                
                                    if srcAS == as_path:
                                        run['origin'] += 1
                                        orig = True
                                        #print "\t\tOrigin\n\n"
                                    elif dstAS == as_path:
                                        run['destination'] += 1
                                        dst = True
                                        #print "\t\tDestination\n\n"
                                    else:
                                        run['middle'] += 1
                                        mid = True
                                        #print "\t\tMiddle\n\n"
                                previous = False
                                
                        if orig and mid and not dst:
                            run['om'] += 1
                        elif orig and dst and not mid:
                            run['od'] += 1
                        elif dst and mid and not orig:
                            run['md'] += 1
                        elif orig and mid and dst:
                            run['omd'] += 1
                                                   
        sequences = []
        colors = []
        labels = []
        for run in runs:
            port = str(run['dstport'])
            if len(port) == 1:
                port.replace("0", "Default")
            totsum = run['origin'] + run['destination'] + run['middle']
            totsum = max(totsum, 1)
            print "Paris-Traceroute {} {} {}".format(run['protocol'], run['algorithm'], port)
            print "\tOrigin: {}% [{} / {}]".format(round((float(run['origin'])/float(run['total'])),2), run['origin'], run['total'])
            print "\tMiddle: {}% [{} / {}]".format(round((float(run['middle'])/float(run['total'])),2), run['middle'], run['total'])
            print "\tDestination: {}% [{} / {}]".format(round((float(run['destination'])/float(run['total'])),2), run['destination'], run['total'])
            print "\tOrigin-Middle: {}% [{} / {}]".format(round((float(run['om'])/float(run['total'])),2), run['om'], run['total'])
            print "\tOrigin-Dest: {}% [{} / {}]".format(round((float(run['od'])/float(run['total'])),2), run['od'], run['total'])
            print "\tMiddle-Dest: {}% [{} / {}]".format(round((float(run['md'])/float(run['total'])),2), run['md'], run['total'])
            print "\tOrig-Middle-Dest: {}% [{} / {}]".format(round((float(run['omd'])/float(run['total'])),2), run['omd'], run['total'])

    def PlotEditDistance(self, directory, service):
        print "Plotting edit distances"
        distances = []

        runs = [
            # {
            #     'protocol':'none',
            #     'algorithm':'mda',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'black'
            # },
            # {
            #     'protocol':'tcp',
            #     'algorithm':'mda',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'red'
            # },
            {
                'protocol':'tcp',
                'algorithm':'exhaustive',
                'dstport':0,
                'distances':[],
                'color':'blue',
                'linestyle':':'
            },
            {
                'protocol':'icmp',
                'algorithm':'exhaustive',
                'dstport':0,
                'distances':[],
                'color':'red',
                'linestyle':'-.'
            },
            {
                'protocol':'udp',
                'algorithm':'exhaustive',
                'dstport':0,
                'distances':[],
                'color':'green',
                'linestyle':'--'
            },
            # {
            #     'protocol':'tcp',
            #     'algorithm':'hopbyhop',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'darkviolet'
            # },
            # {
            #     'protocol':'icmp',
            #     'algorithm':'hopbyhop',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'orange'
            # },
            # {
            #     'protocol':'udp',
            #     'algorithm':'hopbyhop',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'darkgray'
            # },
            # {
            #     'protocol':'tcp',
            #     'algorithm':'hopbyhop',
            #     'dstport':80,
            #     'distances':[],
            #     'color':'skyblue'
            # },
            # {
            #     'protocol':'tcp',
            #     'algorithm':'hopbyhop',
            #     'dstport':443,
            #     'distances':[],
            #     'color':'fuchsia'
            # }
        ]

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            for tracetcp in exp.tracetcp:
                for ptrace in exp.ptrace:
                    if tracetcp.remoteIP != ptrace.targetIP:
                        continue
                    if ptrace.distance <= 0:
                        continue
                    mindist = sys.maxint
                    if ptrace.ContainPath(tracetcp.hops[:tracetcp.lastHop]):
                        mindist = 0
                    else:
                        mindist = ptrace.EditDistance(tracetcp.hops[:tracetcp.lastHop])
                    #print "Min edit distance in {} for {} using paris-traceroute with {} {} {} = {}".format(exp.filename, tracetcp.remoteIP, ptrace.protocol, ptrace.algorithm, ptrace.targetPort, mindist)
                    
                    for run in runs:
                        if ptrace.algorithm.lower() == run['algorithm'] and ptrace.protocol.lower() == run['protocol']:
                            if run['dstport'] != 0 and run['dstport'] != ptrace.targetPort:
                                continue
                            run['distances'].append(mindist)
                
        sequences = []
        colors = []
        labels = []
        markers = ["v","D","o","^","8","s","p","*","+","x"]
        linestyles = []
        for run in runs:
            if len(run['distances']) <= 0:
                markers = markers[:-1]
                continue

            port = run['dstport']
            # if len(port) == 1:
            #     port.replace("0", "Default")
            sequences.append(run['distances'])
            colors.append(run['color'])
            protocol = run['protocol']
            linestyles.append(run['linestyle'])
            if 'none' in protocol.lower():
                protocol = "udp"
            algorithm = "OnePath"
            new = "Old"
            if run['algorithm'] == ParisTraceroute.EXHAUSTIVE or run['algorithm'] == ParisTraceroute.MDA:
                algorithm = "MDA"
            if run['algorithm'] == ParisTraceroute.MDA:
                new = "New"
            if port != 0:
                labels.append("{} {} {}".format(algorithm, protocol.upper(), port))
            else:
                labels.append("{} {}".format(algorithm, protocol.upper()))
            #labels.append("{} {} {}".format(run['protocol'], run['algorithm'], port))
        Plotter.MultipleCDF("{}/{}_editdistance_{}.pdf".format(directory, self.protocol, service), "Pretend Traceroute - Paris Traceroute Edit Distance", "Edit distance", "CDF", sequences, colors, labels, markers, linestyles=linestyles)

    def PlotDistances(self, directory, service):
        print "Plotting distances of all tools"
        distances = []

        runs = [
            # {
            #     'protocol':'none',
            #     'algorithm':'mda',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'black'
            # },
            # {
            #     'protocol':'tcp',
            #     'algorithm':'mda',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'red'
            # },
            {
                'protocol':'tcp',
                'algorithm':'exhaustive',
                'dstport':0,
                'distances':[],
                'color':'blue',
                'linestyle': ':'
            },
            {
                'protocol':'icmp',
                'algorithm':'exhaustive',
                'dstport':0,
                'distances':[],
                'color':'red',
                'linestyle': '-.'
            },
            {
                'protocol':'udp',
                'algorithm':'exhaustive',
                'dstport':0,
                'distances':[],
                'color':'green',
                'linestyle': '--'
            },
            # {
            #     'protocol':'tcp',
            #     'algorithm':'hopbyhop',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'darkviolet'
            # },
            # {
            #     'protocol':'icmp',
            #     'algorithm':'hopbyhop',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'orange'
            # },
            # {
            #     'protocol':'udp',
            #     'algorithm':'hopbyhop',
            #     'dstport':0,
            #     'distances':[],
            #     'color':'darkgray'
            # },
            # {
            #     'protocol':'tcp',
            #     'algorithm':'hopbyhop',
            #     'dstport':80,
            #     'distance':[],
            #     'color':'skyblue'
            # },
            # {
            #     'protocol':'tcp',
            #     'algorithm':'hopbyhop',
            #     'dstport':443,
            #     'distance':[],
            #     'color':'fuchsia'
            # }
        ]

        tracetcpdistances = []

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            for tracetcp in exp.tracetcp:
                tracetcpdistances.append(tracetcp.lastHop)

        for run in runs:
            rundistance = []
            for exp in self.experiments:
                if not exp.CompareService(service):
                    continue
                for pt in exp.ptrace:
                    if pt.distance <= 0:
                        continue
                    if pt.algorithm.lower() == run['algorithm'] and pt.protocol.lower() == run['protocol']:
                        if run['dstport'] != 0 and run['dstport'] != pt.targetPort:
                            continue
                        rundistance.append(pt.distance)
            run['distance'] = rundistance

        sequences = []
        colors = []
        labels = []
        linestyles = []
        #11 markers
        markers = ["D","o","v","^","8","s","p","*","+","x"]
        sequences.append(tracetcpdistances)
        colors.append("black")
        labels.append("Service Traceroute")
        linestyles.append("-")
        for run in runs:
            if len(run['distance']) <= 0:
                markers = markers[:-1]
                continue
            port = run['dstport']
            # if len(port) == 1:
            #     port.replace("0", "Default")
            sequences.append(run['distance'])
            linestyles.append(run['linestyle'])
            colors.append(run['color'])
            protocol = run['protocol']
            if 'none' in protocol.lower():
                protocol = "udp"
            algorithm = "OnePath"
            new = "Old"
            if run['algorithm'] == ParisTraceroute.EXHAUSTIVE or run['algorithm'] == ParisTraceroute.MDA:
                algorithm = "MDA"
            if run['algorithm'] == ParisTraceroute.MDA:
                new = "New"
            if port != 0:
                labels.append("{} {} {}".format(algorithm, protocol.upper(), port))
            else:
                labels.append("{} {}".format(algorithm, protocol.upper()))
        Plotter.MultipleCDF("{}/{}_distances_{}.pdf".format(directory, self.protocol, service), "Pretend Traceroute - Paris Traceroute Distances", "Distance from last replying hop", "CDF", sequences, colors, labels, markers, linestyles=linestyles)

                
        # for run in runs:
        #     port = str(run['dstport'])
        #     if len(port) == 1:
        #         port.replace("0", "Default")
        #     Plotter.Histogram("{}/paristraceroute_distance_{}_{}_{}_{}.pdf".format(directory, run['protocol'], run['algorithm'], run['dstport'], service), "ParisTraceroute Distance [{}, {}, port {}]".format(run['protocol'].replace("none","udp"), run['algorithm'], port), "Distance of last replying hop", "Number of flows", run['distance'], 1)

    def PlotToolMatches(self, directory, service):
        print "Plotting number of matches with each tool"
        runs = [
            {
                'protocol':'none',
                'algorithm':'mda',
                'dstport':0,
                'matches':0,
                'total':0
            },
            {
                'protocol':'tcp',
                'algorithm':'mda',
                'dstport':0,
                'matches':0,
                'total':0
            },
            {
                'protocol':'tcp',
                'algorithm':'exhaustive',
                'dstport':0,
                'matches':0,
                'total':0
            },
            {
                'protocol':'icmp',
                'algorithm':'exhaustive',
                'dstport':0,
                'matches':0,
                'total':0
            },
            {
                'protocol':'udp',
                'algorithm':'exhaustive',
                'dstport':0,
                'matches':0,
                'total':0
            },
            {
                'protocol':'tcp',
                'algorithm':'hopbyhop',
                'dstport':0,
                'matches':0,
                'total':0
            },
            {
                'protocol':'icmp',
                'algorithm':'hopbyhop',
                'dstport':0,
                'matches':0,
                'total':0
            },
            {
                'protocol':'udp',
                'algorithm':'hopbyhop',
                'dstport':0,
                'matches':0,
                'total':0
            },
            {
                'protocol':'tcp',
                'algorithm':'hopbyhop',
                'dstport':80,
                'matches':0,
                'total':0
            },
            {
                'protocol':'tcp',
                'algorithm':'hopbyhop',
                'dstport':443,
                'matches':0,
                'total':0
            }
        ]

        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            for tracetcp in exp.tracetcp:
                for ptrace in exp.ptrace:
                    if tracetcp.remoteIP != ptrace.targetIP:
                        continue
                    match = ptrace.ContainPath(tracetcp.hops[:tracetcp.lastHop])
                    # print "Does the path match in {} for {} using paris-traceroute with {} {} {}? {}".format(exp.filename, tracetcp.remoteIP, ptrace.protocol, ptrace.algorithm, ptrace.targetPort, match)
                    for run in runs:
                        if ptrace.algorithm.lower() == run['algorithm'] and ptrace.protocol.lower() == run['protocol']:
                            if run['dstport'] != 0 and run['dstport'] != ptrace.targetPort:
                                continue
                            run['total'] += 1
                            if match:
                                run['matches'] += 1

        labels = []
        matches = []

        for run in runs:
            if run['total'] <= 0:
                continue
            port = run['dstport']
            # if len(port) == 1:
            #     port.replace("0", "Default")
            protocol = run['protocol']
            if 'none' in protocol.lower():
                protocol = "udp"
            algorithm = "OnePath"
            new = "Old"
            if algorithm == ParisTraceroute.EXHAUSTIVE or algorithm == ParisTraceroute.MDA:
                protocol = "MultiPath"
            if algorithm == ParisTraceroute.MDA:
                new = "New"
            if port != 0:
                labels.append("{} {} {} ({})".format(algorithm, protocol.upper(), port, new))
            else:
                labels.append("{} {} ({})".format(algorithm, protocol, new))

            #run['algorithm'] = run['algorithm'].replace("mda", "MDA").replace("hopbyhop", "HopByHop").replace("exhaustive","Exhaustive")

            #labels.append("{} {} {}".format(run['protocol'].replace("none","udp").upper(), run['algorithm'], port))
            matches.append(float(run['matches'])/float(run['total']))

            # print "{} has {}% of matches".format(labels[-1], matches[-1])

        
        Plotter.HorizontalBar(directory+"/{}_tool_matches_{}.pdf".format(self.protocol, service), "Pretend Traceroute and Paris Traceroute matches", "% of matches", labels, matches)

    def PlotThroughput(self, directory, service_unused):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Video/TCP (with)",
                'label_nt': "Video/TCP (without)",
            },
            {
                'service':"youtube",
                'protocol':Packet.UDP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Youtube/UDP (with)",
                'label_nt': "Youtube/UDP (without)",
            },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Webpages (with)",
                'label_nt': "Webpages (without)",
            }]

        print "Plotting throughput"

        binsize = 5

        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue

                for throughtput in exp.throughput_trace:
                    # if len(throughtput) <= 10: #less than 10 seconds
                    #     continue

                    #conversion to 5s bin
                    array = []

                    for i in range(len(throughtput)):
                        if i % binsize == 0:
                            array.append(0)
                        index = int(i / binsize)
                        array[index] += throughtput[i]

                    service['trace'].extend([int(th/(1024*binsize)+0.5) for th in array])

                for throughtput in exp.throughput_notrace:
                    # if len(throughtput) <= 10: #less than 10 seconds
                    #     continue

                    #conversion to 5s bin
                    array = []

                    for i in range(len(throughtput)):
                        if i % binsize == 0:
                            array.append(0)
                        index = int(i / binsize)
                        array[index] += throughtput[i]
                        
                    service['notrace'].extend([int(th/(1024*binsize)+0.5) for th in array])
            
        sequences = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        linestyles = []
        labels = []
        
        for service in services:
            if service['trace'] == []:
                colors = colors[:-2]
                markers = markers[:-2]
                continue
            sequences.append(service['trace'])
            sequences.append(service['notrace'])
            linestyles.append(":")
            linestyles.append("-.")
            # colors.append("red")
            # colors.append("blue")
            labels.append(service['label_t'])
            labels.append(service['label_nt'])

        Plotter.MultipleCDF("{}/{}_throughtput_{}.pdf".format(directory, self.protocol, service_unused), "Throughput", "Throughput [KB/s] ", "CDF", sequences, colors, labels, markers, linestyles=linestyles, xmax=100, binsize=2)
        #Plotter.MultipleCDF("{}/{}_distances_{}.pdf".format(directory, self.protocol, service), "Pretend Traceroute - Paris Traceroute Distances", "Distance from last replying hop", "CDF", sequences, colors, labels, markers)

    def PlotThroughputDiffCDF(self, directory, service_unused):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Netflix + Youtube \ TCP"
            },
            {
                'service':"youtube",
                'protocol':Packet.UDP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Youtube \ UDP"
            },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Web pages"
            }]

        print "Plotting throughput"
        trace = []
        notrace = []

        maxlen = 0
        binsize = 1

        #Get maximum length
        for exp in self.experiments:
            for throughput in exp.throughput_trace:
                maxlen = max(maxlen, len(throughput))
            for throughput in exp.throughput_notrace:
                maxlen = max(maxlen, len(exp.throughput_notrace))

        #maxlen is in seconds, since bins are 1s each one
        maxlen = int(maxlen / binsize) + 1
        x = [binsize*x for x in list(np.arange(maxlen+1))]


        for service in services:
            service['trace'] = [0]+[0]*maxlen
            service['notrace'] = [0]+[0]*maxlen
            service['diff'] = [0]+[0]*maxlen

            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != self.protocol:
                    continue

                for throughtput in exp.throughput_trace:
                    if len(throughtput) <= 10: #less than 10 seconds
                        continue
                    for i in range(len(throughtput)):
                        index = int(i / binsize)
                        service['trace'][index+1] += throughtput[i]

                for throughtput in exp.throughput_notrace:
                    if len(throughtput) <= 10: #less than 10 seconds
                        continue
                    for i in range(len(throughtput)):
                        index = int(i / binsize)
                        service['notrace'][index+1] += throughtput[i]

            for i in range(len(service['trace'])):
                service['diff'][i] = abs(service['trace'][i] - service['notrace'][i])
            
        sequences = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        labels = []
        
        for service in services:
            if service['diff'] == [0]+[0]*maxlen:
                colors = colors[:-1]
                markers = markers[:-1]
                continue
            sequences.append([th/1024 for th in service['diff']])
            
            labels.append(service['label'])
            #labels.append("{} - Throughput (- Pretend T.)".format(service['service']))

        Plotter.MultiXY("{}/{}_throughtput_diff_{}.pdf".format(directory, self.protocol, service_unused), "Throughput Difference", "Time [s]", "Data [KB]", 0,0, x, sequences, colors, labels, markers)

    def PlotAvgThroughput(self, directory, service_unused):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Video/TCP (with)",
                'label_nt': "Video/TCP (without)",
            },
            {
                'service':"youtube",
                'protocol':Packet.UDP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Youtube/UDP (with)",
                'label_nt': "Youtube/UDP (without)",
            },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Web pages (with)",
                'label_nt': "Web pages (wuthout)",
            }]

        print "Plotting avg throughput"
        trace = []
        notrace = []

        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue
                
                service['trace'].extend([int(y)/1024 for y in exp.avg_throughput_trace])
                service['notrace'].extend([int(y)/1024 for y in exp.avg_throughput_notrace])
                #print "{} has lifetime of {}".format(exp.filename, exp.lifetimeTrace)

        # int_trace = []
        # int_notrace = []

        # for elem in trace:
        #     int_trace.append(int(elem))
        # for elem in notrace:
        #     int_notrace.append(int(elem))

        sequences = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        linestyles = []
        labels = []
        
        for service in services:
            if len(service['trace']) <= 0:
                colors = colors[:-2]
                markers = markers[:-2]
                continue
            sequences.append(service['trace'])
            sequences.append(service['notrace'])
            linestyles.append(":")
            linestyles.append("-.")
            # colors.append("red")
            # colors.append("blue")
            labels.append(service['label_t'])
            labels.append(service['label_nt'])

        Plotter.MultipleCDF("{}/{}_throughtput_avg_{}.pdf".format(directory, self.protocol, service_unused), "Average flow data rate", "Data rate [KB/s]", "CDF", sequences, colors, labels, markers,linestyles=linestyles, binsize=20, xmax=1000)

    def PlotLifeTime(self, directory, service_unused):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Video/TCP (with)",
                'label_nt': "Video/TCP (without)",
            },
            {
                'service':"youtube",
                'protocol':Packet.UDP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Youtube/UDP (with)",
                'label_nt': "Youtube/UDP (without)",
            },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Webpages (with)",
                'label_nt': "Webpages (without)",
            }]

        print "Plotting lifetimes"
        trace = []
        notrace = []

        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue

                service['trace'].extend([int(y) for y in exp.lifetimeTrace])
                service['notrace'].extend([int(y) for y in exp.lifetimeNoTrace])
                #print "{} has lifetime of {}".format(exp.filename, exp.lifetimeTrace)

                if exp.lifetimeTrace != []:
                    if max(exp.lifetimeTrace) > 500:
                        print "{} has duration of {}".format(exp.filename, exp.lifetimeTrace)
                if exp.lifetimeNoTrace != []:
                    if max(exp.lifetimeNoTrace) > 500:
                        print "{} has duration of {}".format(exp.filename, exp.lifetimeNoTrace)

        # int_trace = []
        # int_notrace = []

        # for elem in trace:
        #     int_trace.append(int(elem))
        # for elem in notrace:
        #     int_notrace.append(int(elem))

        sequences = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        linestyles = []
        labels = []
        
        for service in services:
            if len(service['trace']) <= 0:
                colors = colors[:-2]
                markers = markers[:-2]
                continue
            sequences.append(service['trace'])
            sequences.append(service['notrace'])
            linestyles.append(":")
            linestyles.append("-.")
            # colors.append("red")
            # colors.append("blue")
            labels.append(service['label_t'])
            labels.append(service['label_nt'])

        Plotter.MultipleCDF("{}/{}_lifetime_{}.pdf".format(directory, self.protocol, service_unused), "Flow Duration", "Duration [s]", "CDF", sequences, colors, labels, markers, linestyles=linestyles, binsize=20, xmax=500)


        # Plotter.Histogram(directory+"/lifetime_trace_{}.pdf".format(service), "Flows Lifetime (TraceTCP)", "Lifetime of flows", "Number of flows", int_trace, 1, xmax=100)
        # Plotter.Histogram(directory+"/lifetime_notrace_{}.pdf".format(service), "Flows Lifetime (No TraceTCP)", "Lifetime of flows", "Number of flows", int_notrace, 1, xmax=100)

    def PlotWindowDifference(self, directory, service_old):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_nt': 'Video/TCP (witout)',
                'label_t': 'Video/TCP (with)'
            },
            # {
            #     'service':"youtube",
            #     'protocol':Packet.UDP,
            #     'trace':[],
            #     'notrace':[],
            #     'diff': [],
            # },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_nt': 'Webpages (without)',
                'label_t': 'Webpages (with)'
            }]

        print "Plotting window sizes"
        trace = []
        notrace = []

        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue
                service['trace'].extend(exp.windowDifference_trace)
                service['notrace'].extend(exp.windowDifference_notrace)
                #print "{} has lifetime of {}".format(exp.filename, exp.lifetimeTrace)

        # int_trace = []
        # int_notrace = []

        # for elem in trace:
        #     int_trace.append(int(elem))
        # for elem in notrace:
        #     int_notrace.append(int(elem))

        sequences = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        linestyles = []
        labels = []
        
        for service in services:
            if len(service['trace']) <= 0 or service['trace'] == []:
                colors = colors[:-2]
                markers = markers[:-2]
                continue
            sequences.append(service['trace'])
            sequences.append(service['notrace'])
            linestyles.append(":")
            linestyles.append("-.")
            # colors.append("red")
            # colors.append("blue")
            labels.append(service['label_t'])
            labels.append(service['label_nt'])

        Plotter.MultipleCDF("{}/{}_wsize_{}.pdf".format(directory, self.protocol, service_old), "Window Size Difference", "Max WSize - Min WSize", "CDF", sequences, colors, labels, markers,linestyles=linestyles, binsize=200, xmax=8000)
        
    def PlotRetransmissions(self, directory, service_old):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Video/TCP (with)",
                'label_nt': "Video/TCP (without)",
            },
            # {
            #     'service':"youtube",
            #     'protocol':Packet.UDP,
            #     'trace':[],
            #     'notrace':[],
            #     'diff': [],
            # },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label_t': "Webpages (with)",
                'label_nt': "Webpages (without)",
            }]
            
        print "Plotting retransmissions"
        nretr_trace = []
        nretr_notrace = []


        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue
                service['trace'].extend(exp.nretr_trace)
                service['notrace'].extend(exp.nretr_notrace)
                if max(exp.nretr_trace) > 0:
                    print "{} has retransmitted {} times".format(exp.filename, exp.nretr_trace)

        sequences = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        labels = []
        linestyles = []
        for service in services:
            if len(service['trace']) <= 0:
                colors = colors[:-2]
                continue
            sequences.append(service['trace'])
            sequences.append(service['notrace'])
            linestyles.append(":")
            linestyles.append("-.")
            # colors.append("red")
            # colors.append("blue")
            labels.append(service['label_t'])
            labels.append(service['label_nt'])

        Plotter.MultipleCDF("{}/{}_retransmissions_{}.pdf".format(directory, self.protocol, service_old), "Retransmissions", "Number of retransmissions", "CDF", sequences, colors, labels, markers,linestyles=linestyles, binsize=2, xmax=70, logscale=False)
        
        # Plotter.Cdf(directory+"/retransmission_trace_{}.pdf".format(service),"Server Retransmissions (TraceTCP)", "Number of retransmissions", "CDF", 0, 1, nretr_trace)
        # Plotter.Cdf(directory+"/retransmission_notrace_{}.pdf".format(service),"Server Retransmissions (TraceTCP)", "Number of retransmissions", "CDF", 0, 1, nretr_notrace)

    def PlotCurlDifference(self, directory, service):
        print "Plotting curl differences (useless)"
        percentage = [0,0]
        labels = ["Same","Different"]
        
        for exp in self.experiments:
            if not exp.CompareService(service):
                continue
            if exp.CompareCurl():
                percentage[0] += 1
            else:
                percentage[1] += 1

        totalsum = sum(percentage)

        percentage[0] = float(percentage[0]) / float(totalsum)
        percentage[1] = float(percentage[1]) / float(totalsum)

        Plotter.Pie(directory+"/samecurl_{}.pdf".format(service),"Curl download compariso (With TraceTCP vs Without TraceTCP)", labels, percentage)
        
    def PlotDifferenceLifetime(self, directory, service_unused):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Video/TCP",
                'linestyle': ':'
            },
            {
                'service':"youtube",
                'protocol':Packet.UDP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Youtube/UDP",
                'linestyle': '--'
            },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Web pages",
                'linestyle': '-.'
            }]

        print "Plotting lifetimes"
        trace = []
        notrace = []

        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue
                service['trace'].extend([int(y) for y in exp.lifetimeTrace])
                service['notrace'].extend([int(y) for y in exp.lifetimeNoTrace])
                #print "{} has lifetime of {}".format(exp.filename, exp.lifetimeTrace)

        sequences1 = []
        sequences2 = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        linestyles = []
        labels = []
        
        for service in services:
            if len(service['trace']) <= 0:
                colors = colors[:-1]
                markers = markers[:-1]
                continue
            sequences1.append(service['trace'])
            sequences2.append(service['notrace'])
            linestyles.append(service['linestyle'])
            # colors.append("red")
            # colors.append("blue")
            labels.append(service['label'])
            #labels.append("{} - Flow Duration (- Pretend T.)".format(service['service']))

        Plotter.MultipleDiffCDF("{}/{}_lifetime_diff_{}.pdf".format(directory, self.protocol, service_unused), "Flow Duration", "Difference of duration distributions [s]", "CDF", sequences1,sequences2, colors, labels, markers, linestyles=linestyles, binsize=5, xmax=100, xmin=-100)

    def PlotDifferenceRetransmissions(self, directory, service_unused):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Video/TCP",
                'linestyle': ':'
            },
            # {
            #     'service':"youtube",
            #     'protocol':Packet.UDP,
            #     'trace':[],
            #     'notrace':[],
            #     'diff': [],
            # },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Web pages"
                ,
                'linestyle': '-.'
            }]

        print "Plotting difference retransmissions"

        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue
                service['trace'].extend(exp.nretr_trace)
                service['notrace'].extend(exp.nretr_notrace)
            
        sequences1 = []
        sequences2 = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        linestyles = []
        labels = []
        
        for service in services:
            if len(service['trace']) <= 0:
                colors = colors[:-1]
                markers = markers[:-1]
                continue
            sequences1.append(service['trace'])
            sequences2.append(service['notrace'])
            linestyles.append(service['linestyle'])

            labels.append(service['label'])

        Plotter.MultipleDiffCDF("{}/{}_retransmission_diff_{}.pdf".format(directory, self.protocol, service_unused), "Retransmission", "Difference of retransmissions distributions", "CDF", sequences1, sequences2, colors, labels, markers, linestyles=linestyles, binsize=1, xmax=20, xmin=-20)

    def PlotDifferenceWindowSizeDifference(self, directory, service_unused):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Video/TCP",
                'linestyle': ':'
            },
            # {
            #     'service':"youtube",
            #     'protocol':Packet.UDP,
            #     'trace':[],
            #     'notrace':[],
            #     'diff': [],
            # },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Web pages",
                'linestyle': '-.'
            }]

        print "Plotting difference window size"

        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue
                service['trace'].extend(exp.windowDifference_trace)
                service['notrace'].extend(exp.windowDifference_notrace)
            
        sequences1 = []
        sequences2 = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        labels = []
        linestyles = []
        
        for service in services:
            if len(service['trace']) <= 0:
                colors = colors[:-1]
                markers = markers[:-1]
                continue
            sequences1.append(service['trace'])
            sequences2.append(service['notrace'])
            linestyles.append(service['linestyle'])

            labels.append(service['label'])

        Plotter.MultipleDiffCDF("{}/{}_wisze_diff_{}.pdf".format(directory, self.protocol, service_unused), "Window Size", "Difference of window size distributions", "CDF", sequences1, sequences2, colors, labels, markers, linestyles=linestyles,binsize=5, xmax=100, xmin=-100)

    def PlotThroughputDiff(self, directory, service_unused):
        services = [
            {
                'service':"video",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Video/TCP",
                'linestyle': ':'
            },
            {
                'service':"youtube",
                'protocol':Packet.UDP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Youtube/UDP",
                'linestyle': '--'
            },
            {
                'service':"webpage",
                'protocol':Packet.TCP,
                'trace':[],
                'notrace':[],
                'diff': [],
                'label':"Web pages",
                'linestyle': '-.'
            }]

        print "Plotting throughput"
        
        binsize = 5

        for service in services:
            for exp in self.experiments:
                if not exp.CompareService(service['service']) or service['protocol'] != exp.protocol:
                    continue

                for throughtput in exp.throughput_trace:
                    # if len(throughtput) <= 10: #less than 10 seconds
                    #     continue

                    #conversion to 5s bin
                    array = []

                    for i in range(len(throughtput)):
                        if i % binsize == 0:
                            array.append(0)
                        index = int(i / binsize)
                        array[index] += throughtput[i]

                    service['trace'].extend([int(th/(1024*binsize)+0.5) for th in array])

                for throughtput in exp.throughput_notrace:
                    # if len(throughtput) <= 10: #less than 10 seconds
                    #     continue

                    #conversion to 5s bin
                    array = []

                    for i in range(len(throughtput)):
                        if i % binsize == 0:
                            array.append(0)
                        index = int(i / binsize)
                        array[index] += throughtput[i]
                        
                    service['notrace'].extend([int(th/(1024*binsize)+0.5) for th in array])
            
        sequences1 = []
        sequences2 = []
        colors = ["red","orange","navy","skyblue", "green","orchid"]
        markers = [".","+","*","D","o","v","^","8","s","p","*","+","x"]
        linestyles = []
        labels = []
        
        for service in services:
            if service['trace'] == []:
                colors = colors[:-1]
                markers = markers[:-1]
                continue
            sequences1.append(service['trace'])
            sequences2.append(service['notrace'])
            linestyles.append(service['linestyle'])
            # colors.append("red")
            # colors.append("blue")
            labels.append(service['label'])
            #labels.append("{} - Throughput (- Pretend T.)".format(service['service']))

        Plotter.MultipleDiffCDF("{}/{}_throughtput_diff_{}.pdf".format(directory, self.protocol, service_unused), "Throughput", "Difference of throughput distributions [KBps] ", "CDF", sequences1, sequences2, colors, labels, markers, linestyles=linestyles, xmax=30, xmin=-30, binsize=2)
        #Plotter.MultipleCDF("{}/{}_distances_{}.pdf".format(directory, self.protocol, service), "Pretend Traceroute - Paris Traceroute Distances", "Distance from last replying hop", "CDF", sequences, colors, labels, markers)


 
def main(protocol, dir_logs, dir_res, json_file,service,planetlab, overwrite,json_file1="", json_file2=""):
    directories = os.listdir(dir_logs)

    dirs = []

    for directory in directories:
        if os.path.isdir(dir_logs+"/"+directory):
            dirs.append(directory)
    
    servers = [
        "kulcha.mimuw.edu.pl",
        #"node2.planetlab.uni-luebeck.de",
        #"onelab2.pl.sophia.inria.fr",
        "planetlab2.informatik.uni-goettingen.de",
        "planetlab11.net.in.tum.de",
        "planetlab13.net.in.tum.de",
        "planetvs2.informatik.uni-stuttgart.de",
        "ple1.planet-lab.eu",
        #"ple2.hpca.ual.es",
        "ple41.planet-lab.eu",
        "ple43.planet-lab.eu",
        "ple44.planet-lab.eu",
        #"puri.mimuw.edu.pl",
    ]
    prot = Packet.TCP
    if protocol.lower() == "udp":
        prot = Packet.UDP

    exps = Experiments(prot)
    
    try:
        if not overwrite:
            exps.FromFile(json_file)
            exps.FromFile(json_file1)
            exps.FromFile(json_file2)
        else:
            raise Exception("Overwrite :)")
    except:
        for directory in dirs:
            if planetlab:
                for server in servers:
                    exps.Load("{}/{}/{}".format(dir_logs,directory,server),startingIndex=int(directory.split("-")[0])+1, max_iterations=1)
            else:
                exps.Load("{}/{}".format(dir_logs,directory),startingIndex=int(directory.split("-")[0])+1, max_iterations=1)
        exps.ToFile(json_file)

    matplotlib.rcParams.update({'font.size': 17})
    matplotlib.rc('legend', fontsize=12)
    exps.PlotRSTS(dir_res, service)
    exps.PlotFlowsSize(dir_res, service)
    exps.PlotOldProbes(dir_res, service)
    exps.PlotTraceDistance(dir_res, service)
    exps.PlotDistances(dir_res, service)
    exps.PlotLifeTime(dir_res, service)
    exps.PlotDifferenceLifetime(dir_res, service)
    exps.PlotThroughput(dir_res, service)
    exps.PlotAvgThroughput(dir_res, service)
    exps.PlotThroughputDiff(dir_res, service)
    exps.PlotWindowDifference(dir_res, service)
    exps.PlotDifferenceWindowSizeDifference(dir_res, service)
    exps.PlotRetransmissions(dir_res, service)
    exps.PlotDifferenceRetransmissions(dir_res, service)
    exps.PlotCurlDifference(dir_res, service)
    exps.PlotRSTSBeforeStreamEnd(dir_res, service)
    exps.PlotToolMatches(dir_res, service)
    exps.PlotTraceTCPPathChanges(dir_res, service)
    exps.PlotEditDistance(dir_res, service)
    print len(exps.experiments)

    #Print
    exps.PrintPathChangePos(service)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze PCAP and LOG file of TraceTCP experiment')
    parser.add_argument('--dir', help='directory with the results')
    parser.add_argument('--res', help='directory for the results')
    parser.add_argument('--json', help='file containing all data')
    parser.add_argument("--service", default="all", help='type of service')
    parser.add_argument("--planetlab", default="no", help="if planetlab are used: 'yes', else 'no'")
    parser.add_argument("--overwrite", default="no", help="overwrite json file. 'yes' or 'no'")
    parser.add_argument("--add", default="", help="add a secondary json")
    parser.add_argument("--adds", default="", help="add a secondary json")
    parser.add_argument("--protocol",default="tcp", help="protocol used during the analysis: 'udp' or 'tcp'")
    # parser.add_argument('--pcap', default=PCAP_FILE,
    #                     help='pcap file to analyze')
    # parser.add_argument('--log', default=LOG_FILE,
    #                     help='log file to analyze')

    res = parser.parse_args()

    overwrite = False
    planetlab = False
    if res.overwrite.lower() == "yes":
        overwrite = True
    if res.planetlab.lower() == "yes":
        planetlab = True
    
    # Utils.LoadMap("map.dat")
    main(res.protocol, res.dir, res.res, res.json,res.service, planetlab, overwrite, res.add, res.adds)
    # Utils.StoreMap("map.dat")
    # Utils.StoreMapMissingIP("missingmap.dat")