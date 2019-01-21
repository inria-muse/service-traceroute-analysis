from datetime import datetime
from multiprocessing import Process
from threading import Thread
import signal
import threading
import time
import subprocess
import sys
import os
import json
import servicetraceroute

class Printer:
    mutex = threading.Semaphore()
    @staticmethod
    def Print(string):
        Printer.mutex.acquire()
        timestamp = str(datetime.now())
        print timestamp, ": ", string
        sys.stdout.flush()
        Printer.mutex.release()

class OSystem:
    UBUNTU = "ubuntu"
    FEDORA = "fedora"
    MAC = "mac"
    RPI3 = "rpi3"

#modify tracetcp to accept several options
class TraceTCP:
    COMMAND = 'sudo {} -iface {} {} {} -distance {} -iterations {} -output json -timeout {} -flowtimeout {} -ipt {} -itt {} -algorithm {} -idle {} -stop {} -start={} -lifetime {} > {} 2>&1'
    PACKET = "packetbypacket"
    TRAIN = "hopbyhop"
    ALL = "concurrent"

    def __init__(self, command, iface):
        self.command = command
        self.iface = iface
        self.thread = None
        self.listener = None
        self.close = True
        self.lifetime = 600
        self.SetParameters()

    @staticmethod
    def getRemoteIPsFromFile(filename):
        remoteIPs = []
        f = open(filename)

        #Parse TraceTCP experiments from the log file
        for line in f:
            #Check that we have the json and not other text
            if line[0] != '{':
                continue

            tracetcp = servicetraceroute.TraceTCP(json.loads(line))
            if tracetcp.remoteIP not in remoteIPs:
                remoteIPs.append(tracetcp.remoteIP)
        f.close()
        return remoteIPs

    @staticmethod
    def getIdentifier(filename):
        array = []
        f = open(filename)

        #Parse TraceTCP experiments from the log file
        for line in f:
            #Check that we have the json and not other text
            if line[0] != '{':
                continue

            tracetcp = servicetraceroute.TraceTCP(json.loads(line))
            tcpid = (tracetcp.remoteIP, tracetcp.localPort, tracetcp.remotePort)
            if tcpid not in array:
                array.append(tcpid)
        f.close()
        return array

    def SetParameters(self, hosts=[], services=[], distance=32, iterations=3, interProbeTime=20, interIterationTime=100, timeout=2000, flowTimeout=0, idleTime=120,stopAfter=120, lifetime=600,sendingAlgorithm=PACKET):
        self.hosts = hosts
        self.services = services
        self.distance = distance
        self.iterations = iterations
        self.interProbeTime = interProbeTime
        self.interIterationTime = interIterationTime
        self.sendingAlgorithm = sendingAlgorithm
        self.timeout = timeout
        self.flowtimeout = flowTimeout
        self.lifetime = lifetime
        self.idleTime = idleTime
        self.stopAfter = stopAfter
        self.running = False
        self.process = None
        self.start = True

    def Run(self, filename, timeout, callback=None, killAfterTimeout=False):
        hosts = ""
        for host in self.hosts:
            hosts+="--hosts {} ".format(host)
        services = ""
        for service in self.services:
            services += "--services {} ".format(service)
        command = TraceTCP.COMMAND.format(self.command, self.iface, hosts, services, self.distance, self.iterations, self.timeout, self.flowtimeout, self.interProbeTime, self.interIterationTime, self.sendingAlgorithm, self.idleTime, self.stopAfter, self.start, self.lifetime, filename)
        Printer.Print(command)
        self.running = True
        stopThread = None
        if killAfterTimeout:
            stopThread = Thread(target = self.KillAfterTimeout, args = (self.lifetime*2, ))
            stopThread.start()
        os.system(command)
        self.running = False
        if killAfterTimeout:
            stopThread.join()
        self.process = None
        time.sleep(10)
        if callback:
            callback()
        self.close = True

    def KillAfterTimeout(self, timeout):
        now = time.time()
        Printer.Print("Waiting {} seconds before killing Service Traceroute".format(timeout))
        while (time.time() - now) < timeout and self.running:
            time.sleep(1)

        Printer.Print("Killing service traceroute")
        self.Kill()

    def Kill(self):
        name = self.command
        if '/' in name:
            name = name[name.rindex('/')+1:]
        command = 'sudo kill -9 {}'.format(name)
        Printer.Print(command)
        os.system(command)
        # self.process = subprocess.Popen(['sudo', 'pkill','-f',name], stdout=subprocess.PIPE, shell=True)
        # stdout = self.process.communicate()[0]
        Printer.Print("{} Killed".format(name))

    def RunAsynch(self, filename, timeout, callback=None, killAfterTimeout=False):
        self.thread = threading.Thread(name="tracetcp", target=self.Run, args=(filename,timeout,callback, killAfterTimeout))
        self.thread.start()
        time.sleep(10)
        # self.thread = Process(target=self.Run, args=(filename,))
        # self.thread.start()

    def WaitThread(self):
        Printer.Print("Waiting the end of the tracetcp thread")
        if not self.thread:
            return
        self.thread.join()
        Printer.Print("TraceTCP thread closed")

    def ListenerAsynch(self, filename, traceroute, protocol, callback):
        self.listener = threading.Thread(name="listener", target=self.Listener, args=(filename, traceroute, protocol, callback))
        self.listener.start()

    def WaitListener(self):
        Printer.Print("Waiting the end of the tracetcp listener")
        if not self.listener:
            return
        self.listener.join()
        Printer.Print("TraceTCP listener closed")

    #Start the callback when a new result is detected in tracetcp log file
    def Listener(self, filename, traceroute, protocol, callback):
        Printer.Print("Starting listener on the file {}".format(filename))
        lineCounter = 0
        self.close = False
        while not self.close:
            time.sleep(0.01)
            try:
                file = open(filename)
            except:
                continue

            # Printer.Print("Checking file, line read: {}".format(lineCounter))
            counter = 0
            for line in file:
                if self.close:
                    break
                counter += 1

                if lineCounter >= counter:
                    continue

                try:
                    res = json.loads(line.strip())
                    callback(traceroute, res['Data']['TargetIP'], res['Data']['LocalPort'], res['Data']['TargetPort'], protocol, res['Data']['Service'], res['Data']['IPResolution'], res['Data']['FlowEnded'])
                except:
                    pass
                    #Printer.Print("Error on decoding {}".format(line)) 
                
            file.close()
            lineCounter = counter
            time.sleep(1)
        Printer.Print("Listener closed")
        
class ParisTraceroute:
    def __init__(self, osystem, usingManager=True):
        self.process = None
        self.threadMap = {}
        self.queue = []
        self.mapResults = {}
        self.mapMutex = threading.Semaphore()
        self.queueMutex = threading.Semaphore()  
        self.Install(osystem, usingManager)

    def Enqueue(self, destination):
        if destination not in self.queue:
            self.queue.append(destination)

    def RunQueue(self):
        for destination in self.queue:
            self.RunAllProtocolsSequentially(destination)
        self.queue = []

    def Kill(self):
        Printer.Print("Killing paris-traceroute")
        if self.process:
            self.process.kill()

    def IsRunning(self):
        if self.process:
            return self.process.poll() is None
        return False
            
    def Install(self, osystem, usingMangager):
        if osystem==OSystem.FEDORA and usingMangager:
            os.system("sudo yum install paris-traceroute -y")
            return
        if self.CheckParisTracerouteInstallation():
            Printer.Print("Paris-traceroute already installed")
            return
        Printer.Print("Installing paris-traceroute")
        os.system("rm -rf libparistraceroute")
        if osystem == OSystem.FEDORA:
            os.system(". ./install_paris_fedora.sh")
        elif osystem == OSystem.UBUNTU:
            os.system(". ./install_paris_ubuntu.sh")

    def CheckParisTracerouteInstallation(self):
        self.process = subprocess.Popen(['ls', 'libparistraceroute'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = self.process.communicate()[0].lower()
        if stdout != '': 
            return True
        return False

    def RunAllProtocolsSequentially(self, destination, srcPort=33456, dstPort=33457):
        timeout = 150 

        # self.RunTimeout(timeout, destination, "mda", srcPort, dstPort, newversion=True)
        # self.RunTimeout(timeout, destination, "mda", srcPort, dstPort, "tcp", newversion=True)

        self.RunTimeout(timeout, destination, "exhaustive", srcPort, dstPort, "udp", newversion=False)
        self.RunTimeout(timeout, destination, "exhaustive", srcPort, dstPort, "tcp", newversion=False)
        self.RunTimeout(timeout, destination, "exhaustive", srcPort, dstPort, "icmp", newversion=False)

        # self.RunTimeout(timeout, destination, "hopbyhop", srcPort, dstPort, "udp", newversion=False)
        # self.RunTimeout(timeout, destination, "hopbyhop", srcPort, dstPort, "tcp", newversion=False)
        # self.RunTimeout(timeout, destination, "hopbyhop", srcPort, dstPort, "icmp", newversion=False)

        # self.RunTimeout(timeout, destination, "hopbyhop", srcPort, 80, "tcp", newversion=False)
        # self.RunTimeout(timeout, destination, "hopbyhop", srcPort, 443, "tcp", newversion=False)
        #self.Run(destination, srcPort, dstPort, "icmp")

    def RunTimeout(self, timeout, destination, algorithm, srcPort=33456, dstPort=33457, protocol="none" ,newversion=True):
        self.RunAsynch(destination, algorithm, srcPort, dstPort, protocol, newversion)
        start = time.time()

        time.sleep(10)

        while (time.time() - start < timeout) and self.IsRunning():
            time.sleep(1)
        
        if self.IsRunning():
            self.Kill()
        
        self.WaitThread(destination)

        self.process = None

    def RunApt(self, destination, algorithm, srcPort=33456, dstPort=33457, protocol="none"):
        newversion=False
        Printer.Print("Running paris-traceroute to {} with src port {}, dst port {}, protocol {}, algorithm {} and newversion={}".format(destination, srcPort, dstPort, protocol, algorithm, newversion))
        start = time.time()
        
        if protocol.lower() == "icmp":
            self.process = subprocess.Popen(['sudo', 'paris-traceroute','-a',algorithm, "-p", protocol.lower(), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif protocol != "none":
            self.process = subprocess.Popen(['sudo', 'paris-traceroute','-a',algorithm, '-d', str(dstPort), '-s', str(srcPort), "-p", protocol.lower(), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            self.process = subprocess.Popen(['sudo', 'paris-traceroute','-a',algorithm, '-d', str(dstPort), '-s', str(srcPort), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = self.process.communicate()
        end = time.time()
        #Printer.Print("Parsing the result")
        #self.Parse(newversion, destination, stdout)
        self.mapMutex.acquire()
        if destination not in self.mapResults:
            self.mapResults[destination] = []

        result = {
            'result': stdout,
            'protocol': protocol,
            'algorithm': algorithm,
            'destination':destination,
            'srcPort': srcPort,
            'dstPort': dstPort,
            'isNewVersion':False,
            'startTimestamp': start,
            'endTimestamp':end,
            'error':stderr
        }
        
        self.mapResults[destination].append(result)
        self.mapMutex.release()
        Printer.Print("Finished with paris-traceroute")

    def Run(self, destination, algorithm, srcPort=33456, dstPort=33457, protocol="none" ,newversion=True):
        Printer.Print("Running paris-traceroute to {} with src port {}, dst port {}, protocol {}, algorithm {} and newversion={}".format(destination, srcPort, dstPort, protocol, algorithm, newversion))
        start = time.time()
        if newversion:
            if protocol.lower() == "icmp":
                self.process = subprocess.Popen(['sudo', 'libparistraceroute/paris-traceroute/paris-traceroute','-a',algorithm, "--{}".format(protocol.lower()), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif protocol != "none":
                self.process = subprocess.Popen(['sudo', 'libparistraceroute/paris-traceroute/paris-traceroute','-a',algorithm, '-p', str(dstPort), '-s', str(srcPort), "--{}".format(protocol.lower()), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                self.process = subprocess.Popen(['sudo', 'libparistraceroute/paris-traceroute/paris-traceroute','-a',algorithm, '-p', str(dstPort), '-s', str(srcPort), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            if protocol.lower() == "icmp":
                self.process = subprocess.Popen(['sudo', '/home/upmc_netmet/evaluation/paris-traceroute-old','-a',algorithm, "-p", protocol.lower(), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif protocol != "none":
                self.process = subprocess.Popen(['sudo', '/home/upmc_netmet/evaluation/paris-traceroute-old','-a',algorithm, '-d', str(dstPort), '-s', str(srcPort), "-p", protocol.lower(), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                self.process = subprocess.Popen(['sudo', '/home/upmc_netmet/evaluation/paris-traceroute-old','-a',algorithm, '-d', str(dstPort), '-s', str(srcPort), destination], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = self.process.communicate()
        end = time.time()
        #Printer.Print("Parsing the result")
        #self.Parse(newversion, destination, stdout)
        self.mapMutex.acquire()
        if destination not in self.mapResults:
            self.mapResults[destination] = []

        result = {
            'result': stdout,
            'protocol': protocol,
            'algorithm': algorithm,
            'destination':destination,
            'srcPort': srcPort,
            'dstPort': dstPort,
            'isNewVersion':newversion,
            'startTimestamp': start,
            'endTimestamp':end,
            'error':stderr
        }
        
        self.mapResults[destination].append(result)
        self.mapMutex.release()
        Printer.Print("Finished with paris-traceroute")

    def RunAsynch(self, destination, algorithm, srcPort=33456, dstPort=33457, protocol="none" ,newversion=True):
        self.threadMap[destination] = threading.Thread(name="paris-traceroute", target=self.Run, args=(destination, algorithm, srcPort, dstPort, protocol, newversion))
        self.threadMap[destination].start()

    def RunAsynchAllProtocols(self, destination, srcPort=33456, dstPort=33457):
        self.threadMap[destination] = threading.Thread(name="paris-traceroute", target=self.RunAllProtocolsSequentially, args=(destination, srcPort, dstPort))
        self.threadMap[destination].start()

    def WaitThread(self, destination):
        Printer.Print("Waiting the end of the paris traceroute to {}".format(destination))
        if destination in self.threadMap:
            return
        self.threadMap[destination].join()
        Printer.Print("Paris traceroute to {} finished".format(destination))

    def WaitAllThreads(self):
        Printer.Print("Waiting the end of all paris traceroute")
        for dst in self.threadMap:
            self.threadMap[dst].join()
        Printer.Print("All paris traceroute ended")

    def Parse(self, newversion, destination, string):
        if newversion:
            self.ParseMDA(destination, string)
        else:
            self.ParseOldVersion(destination, string)

    def ParseMDA(self, destination, string):
        Printer.Print("Parsing paris-traceroute MDA output")
        self.mapMutex.acquire()
        if destination not in self.mapResults:
            self.mapResults[destination] = []

        result = {
            'result': string
        }

        path = {}

        lines = string.split("\n")

        for line in lines:
            if 'lattice' in line.lower():
                lines = lines[lines.index(line)+1:]
                break

        lines[0] = lines[0].replace("None", "Start")

        starCounter = 0
        lastStar = ""
        for line in lines:
            if line.strip() == "":
                continue
            splittedLine = line.split(" ")
            srcIP = splittedLine[0]

            if "None" in srcIP:
                srcIP = srcIP.replace("None", lastStar)
            if srcIP not in path:
                path[srcIP] = []

            for i in range(1, len(splittedLine)):
                if '.' not in splittedLine[i]:
                    continue

                dstIP = splittedLine[i]
                if "None" in dstIP:
                    starCounter += 1
                lastStar = "None{}".format(starCounter)
                dstIP = dstIP.replace("None", lastStar)
                dstIP = dstIP.replace(",", "")
                path[srcIP].append(dstIP)

        result['path'] = path
        self.mapResults[destination].append(result)
        self.mapMutex.release()

    def ParseOldVersion(self, destination, string):
        self.mapMutex.acquire()
        if destination not in self.mapResults:
            self.mapResults[destination] = []

        res = {
            'duration': 0,
            'hops': []
        }

        for line in string.split("\n"):
            splittedLine = line.split(" ")
            if splittedLine[0].strip() == "#":
                continue
            #first line
            if 'duration' in line:
                duration = line[line.index("duration") + len("duration"):]
                duration = duration[:duration.index("s")]
                res['duration'] = int(duration.strip())

            elif splittedLine[1].isdigit():
                ttl = int(splittedLine[1])
                devices = []
                for i in range(5,len(splittedLine)):
                    #If we find the IP
                    if '(' in splittedLine[i] and ')' in splittedLine[i]:
                        device = {
                            'ip': splittedLine[i][splittedLine[i].index("(")+1:splittedLine[i].index(")")],
                            'ttl': ttl,
                            'min': float(splittedLine[i+2].split("/")[0]),
                            'avg': float(splittedLine[i+2].split("/")[1]),
                            'max': float(splittedLine[i+2].split("/")[2]),
                            'stdev': float(splittedLine[i+2].split("/")[3])
                        }
                        devices.append(device)
                res['hops'].append(devices)
        self.mapResults[destination].append(res)
        self.mapMutex.release()

    def ToFile(self, filename):
        self.mapMutex.acquire()
        file = open(filename, "w")
        json.dump(self.mapResults, file, sort_keys=True, indent=4)
        file.close()
        self.mapMutex.release()

    def Clear(self):
        self.mapMutex.acquire()
        self.mapResults = {}
        self.mapMutex.release()

    def IsEnded(self):
        if self.process == None:
            return True
        if self.process.poll() != None:
            return True
        return False
    
class TCPDump:
    COMMAND = 'sudo tcpdump -i {} tcp or udp or icmp -s 200 -w {}'

    def __init__(self):
        self.process = None
        self.thread = None

    def Start(self, iface, filename):
        command = TCPDump.COMMAND.format(iface, filename)

        Printer.Print(command)
        self.process = subprocess.Popen(command, shell=True)
        time.sleep(5)

    def StartAsynch(self, iface, filename):
        self.thread = threading.Thread(name="tcpdump", target=self.Start, args=(iface, filename))
        self.thread.start()
        time.sleep(10)

    def WaitThread(self):
        Printer.Print("Waiting the end of tcpdump thread")
        if not self.thread:
            return
        self.thread.join()
        Printer.Print("TCPDump thread closed")

    def Kill(self):
        command = 'sudo pkill -f tcpdump'
        Printer.Print(command)
        self.process = subprocess.Popen(['sudo', 'pkill','-f',"tcpdump"], stdout=subprocess.PIPE)
        stdout = self.process.communicate()[0]

class ZeroTrace:
    COMMAND = "sudo python ./library/0trace_fixed.py {} {} {}"

    def __init__(self, iface):
        self.process = None
        self.thread = None
        self.mapResults = []
        self.mapMutex = threading.Semaphore()
        self.iface = iface
        self.running = False

        self.install()

    def install(self):
        # os.system("sudo dnf install python3-devel -y")
        # os.system("sudo dnf reinstall python3-pip -y")
        # os.system("sudo pip3 install pypcap")
        os.system("sudo yum install gcc -y")
        os.system("sudo yum install libpcap-devel -y")
        os.system("sudo dnf install redhat-rpm-config -y")
        os.system("sudo yum install libdnet-python -y")
        # os.system("sudo yum install python-devel --best --allowerasing -y")
        # os.system("sudo yum install libevent-devel -y")
        # os.system("sudo pip install matplotlib")
        # os.system("sudo pip install networkx")
        # os.system("sudo pip install pyyaml")
        os.system("sudo pip install dpkt")
        os.system("sudo pip install pypcap")
        os.system("sudo pip install scapy")
        # os.system("sudo yum install libdnet -y")
        

    def toFile(self, filename):
        self.mapMutex.acquire()
        file = open(filename, "w")
        json.dump(self.mapResults, file, sort_keys=True, indent=4)
        file.close()
        self.mapMutex.release()

    def clear(self):
        self.mapMutex.acquire()
        self.mapResults = []
        self.mapMutex.release()

    def start(self, ip, port):
        Printer.Print("Starting 0Trace to {} with port {}".format(ip, port))
        command = ZeroTrace.COMMAND.format(self.iface, ip, port)

        Printer.Print(command)
        self.running = True

        # stdout = ""

        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = self.process.communicate()

        # Printer.Print(stdout)
        # Printer.Print(stderr)

        # os.system(command)

        self.mapMutex.acquire()
        self.mapResults.append({
            "iface":self.iface,
            "ip":ip,
            "port": port,
            "output":stdout,
            'error':stderr
        })
        self.mapMutex.release()
        self.running = False
        Printer.Print("0Trace ended")
    
    def waitThread(self):
        Printer.Print("Waiting the end of 0trace thread")
        if not self.thread:
            return
        self.thread.join()
        Printer.Print("0trace thread closed")

    def kill(self):
        command = 'sudo pkill -f 0trace.py'
        Printer.Print(command)
        self.process = subprocess.Popen(['sudo', 'pkill','-f',"0trace.py"], stdout=subprocess.PIPE)
        stdout = self.process.communicate()[0]
    
    def killAfterTimeout(self, timeout):
        now = time.time()
        Printer.Print("Waiting {} seconds before killing 0Trace".format(timeout))
        while (time.time() - now) < timeout and self.running:
            time.sleep(1)

        Printer.Print("Killing 0Trace")
        self.kill()

    def startAsynch(self, ip, port):
        if self.running:
            return
        self.thread = threading.Thread(name="zerotrace", target=self.start, args=(ip, port))
        self.thread.start()
