import sys 

from library.utils import *

#filename = "/Users/ivanmorandi/Desktop/Measurements/results_2706/planet4.cs.huji.ac.il/apacket.d32.i1.ip5.ptcp.webpages.it=0.54.ps.log"

class ParisTraceroute:
    MDA = "mda"
    EXHAUSTIVE = "exhaustive"
    HOPBYHOP = "hopbyhop"
    
    def __init__(self, targetIP, targetPort, localPort, protocol, algorithm, tstart, tend, newrelease, string, error):
        self.path = {}
        self.targetIP = targetIP
        self.targetPort = targetPort
        self.localPort = localPort
        self.protocol = protocol
        self.algorithm = algorithm
        self.tstart = tstart
        self.tend = tend
        self.newrelease = newrelease
        self.error = error
        self.Parse(string)
        #print self.path
        self.distance = self.PathLength()

    

    def Parse(self, string):
        if self.algorithm.lower() == ParisTraceroute.MDA:
            self.ParseMDA(string)
        elif self.algorithm.lower() == ParisTraceroute.EXHAUSTIVE:
            self.ParseExhaustive(string)
        # elif self.algorithm.lower() == ParisTraceroute.HOPBYHOP:
        else:
            self.ParseHopbyHop(string)

    def Paths(self):
        #Get DFA order
        print ("Getting DFA order")
        order = self.DFAOrder()
        print ("Obtainin paths")
        #Obtain paths
        order = order[::-1]

        finalpaths = {}

        for ip in order:
            #print "cheking {}".format(ip)
            paths = []
            for elem in self.path[ip]:
                #print "\tadding paths from {} with {} paths".format(elem, len(finalpaths[elem]))
                paths.extend(finalpaths[elem])
            if paths == []:
                paths.append([])
            for i in range(len(paths)):
                paths[i].insert(0, ip)
            finalpaths[ip] = paths

        return finalpaths['Start']
            
    def DFAOrder(self):
        #Get DFA order
        srcIP = "Start"
        stack = []
        order = []
        visited = []

        stack.append(srcIP)

        while stack != []:
            ip = stack.pop(0)
            order.append(ip)

            for elem in self.path[ip]:
                if elem not in visited:
                    stack.append(elem)
                    visited.append(elem)
        return order

    def GetPaths2(self):
        # self.path
        srcIP = "Start"
        paths = []

        queue = []
        visited = []
        queue.append(srcIP)
        visited.append(srcIP)

        if srcIP not in self.path:
            return
        links = 0
        while queue != []:
            srcIP = queue.pop(0)
            links += len(self.path[srcIP])

            #print "{} --> {}\n\n".format(srcIP, self.path[srcIP])
            for elem in self.path[srcIP]:
                if elem not in visited:
                    visited.append(elem)
                    queue.append(elem)
        
        #print len(visited)
        #print links

    def GetPaths(self):
        srcIP = "Start"
        max_length = 0
        queue = []
        used_ip = []

        finalpaths = []

        if srcIP not in self.path:
            return []

        queue.append({"paths":[[]], "ip":srcIP})
        used_ip.append(srcIP)

        while len(queue) > 0:
            srcIP = queue[0]['ip']
            paths = queue[0]['paths']

            #print "{} with {} paths".format(srcIP, len(paths))
            queue = queue[1:]
            used_ip = used_ip[1:]

            for path in paths:
                if "None" in srcIP:
                    path.append("")
                else:
                    path.append(srcIP)

            if self.path[srcIP] == []:
                for path in paths:
                    if path not in finalpaths:
                        finalpaths.append(path[:])

            for elem in self.path[srcIP]:
                if elem not in used_ip:
                    queue.append({"paths":[path[:] for path in paths], "ip":elem})
                    used_ip.append(elem)
                else:
                    for path in paths:
                        if path not in queue[used_ip.index(elem)]['paths']:
                            queue[used_ip.index(elem)]['paths'].append(path[:])
                
        #Remove start
        for i in range(len(finalpaths)):
            for j in range(len(finalpaths[i])):
                finalpaths[i][j] = finalpaths[i][j].split("#")[0]
            finalpaths[i] = finalpaths[i][1:]

        return finalpaths

    def ParseExhaustive(self, string):
        #print ("Parsing exhaustive paristraceroute")
        lines = string.split("\n")

        #Count how many comments are present in the output (lines starting with #)
        comments = 0
        for line in lines:
            if len(line) <= 0:
                continue
            if line[0] == "#":
                comments += 1
            else:
                break
        lines = lines[comments+1:]

        #Start parsing

        counter = {}
        counter['None'] = 0

        self.path["Start"] = []
        srcIPs = ["Start"]
        srcPorts = [[]]

        for line in lines:
            if "MPLS" in line or line.strip() == "":
                continue

            newIPs = []
            newPorts = []
            
            #Parsing
            for elem in line.split(" "):
                if "(" in elem and ")" in elem and "." in elem:
                    ip = elem[1:elem.index(")")]
                    ports = []
                    if ":" in elem:
                        ports = elem.split(":")[1].split(",")

                    newIPs.append(ip)
                    newPorts.append(ports)
                    if ip not in counter:
                        counter[ip] = 0

            if newIPs == []:
                newIPs.append("None")
                newPorts.append([])
                # for i in range(len(srcIPs)):
                #     newIPs.append("None")
                #     newPorts.append(srcPorts[i])
                    
            
            newSrcIPs = []
            newSrcPorts = []

            #Building paths
            for newip_index in range(len(newIPs)):
                newip = newIPs[newip_index]
                newports = newPorts[newip_index]
                number = counter[newip]
                counter[newip] += 1
                modip = newip + "#{}".format(number)

                for srcip_index in range(len(srcIPs)):
                    srcip = srcIPs[srcip_index]
                    srcports = srcPorts[srcip_index]

                    intersection = Utils.Intersection(srcports, newports)
                    if srcports == [] or newports == [] or intersection != []:
                        self.path[srcip].append(modip)
                        
                        if modip not in newSrcIPs:
                            newSrcIPs.append(modip)
                            newSrcPorts.append(newports)

            srcIPs = newSrcIPs
            srcPorts = newSrcPorts

            for srcip in srcIPs:
                if srcip not in self.path:
                        self.path[srcip] = []

        #print self.path

    def ParseExhaustive2(self, string):
        #print ("Parsing exhaustive paristraceroute")
        lines = string.split("\n")

        #Count how many comments are present in the output (lines starting with #)
        comments = 0
        for line in lines:
            if len(line) <= 0:
                continue
            if line[0] == "#":
                comments += 1
            else:
                break
        lines = lines[comments+1:]

        #Start parsing

        counter = {}

        none_format = "None{}"
        none_counter = 0

        self.path["Start"] = []
        srcIPs = ["Start"]
        srcPorts = [[]]

        for line in lines:
            if "MPLS" in line:
                continue

            newIPs = []
            newPorts = []

            for elem in line.split(" "):
                if "(" in elem and ")" in elem and "." in elem:
                    ip = elem[1:elem.index(")")]
                    ports = []
                    if ":" in elem:
                        ports = elem.split(":")[1].split(",")

                    number = 0
                    if ip in counter:
                        number = counter[ip]
                        counter[ip] += 1
                    else:
                        counter[ip] = number+1
                    ip+="#{}".format(number)
                    newIPs.append(ip)
                    newPorts.append(ports)

            if newIPs == []:
                for i in range(len(srcIPs)):
                    newIPs.append(none_format.format(none_counter))
                    newPorts.append(srcPorts[i])
                    none_counter += 1
            
            newSrcIPs = []
            newSrcPorts = []
            for srcip_index in range(len(srcIPs)):
                srcip = srcIPs[srcip_index]
                srcports = srcPorts[srcip_index]

                for newip_index in range(len(newIPs)):
                    newip = newIPs[newip_index]
                    newports = newPorts[newip_index]

                    if srcports == [] or newports == []:
                        self.path[srcip].append(newip)
                    else:
                        for port in srcports:
                            if port in newports:
                                if newip not in self.path[srcip]:
                                    self.path[srcip].append(newip)

                    if newip not in newSrcIPs:
                        newSrcIPs.append(newip)
                        newSrcPorts.append(newports)

            srcIPs = newSrcIPs
            srcPorts = newSrcPorts

            for srcip in srcIPs:
                if srcip not in self.path:
                        self.path[srcip] = []

    #FIX PARSING
    def ParseHopbyHop(self, string):
        print ("Parsing hopbyhop paristraceroute")
        lines = string.split("\n")

        comments = 0
        for line in lines:
            if len(line) <= 0:
                continue
            if line[0] == "#":
                comments += 1
            else:
                break
        lines = lines[comments+1:]
        #lines = lines[1:]

        none_format = "None{}"
        none_counter = 0

        srcIPs = ["Start"]

        counter = {}
        

        for line in lines:
            if "MPLS" in line:
                continue

            newIPs = []

            if "(" not in line and ")" not in line and "." not in line:
                newIPs.append(none_format.format(none_counter))
                none_counter += 1
            else:
                for elem in line.split(" "):
                    if "(" in elem and ")" in elem and "." in elem:
                        ip = elem[1:-1]
                        if ip not in newIPs:
                            newIPs.append(ip)
                            if ip not in counter:
                                counter[ip] = 0

            finalIPs = []
            for srcip in srcIPs:
                if srcip not in self.path:
                    self.path[srcip] = []
                for i in range(len(newIPs)):
                    str = newIPs[i]
                    if "." in newIPs[i]:
                        number = counter[newIPs[i]]
                        counter[newIPs[i]] += 1
                        str += "#{}".format(number)
                    
                    self.path[srcip].append(str)
                    finalIPs.append(str)
            srcIPs = finalIPs

            for srcip in srcIPs:
                if srcip not in self.path:
                    self.path[srcip] = []

    def ParseMDA(self, string):
        print ("Parsing mda paristraceroute")
        self.path = {}
        counter = {}

        lines = string.split("\n")

        if 'lattice' not in string.lower():
            return

        for line in lines:
            if 'lattice' in line.lower():
                lines = lines[lines.index(line)+1:]
                break

        #Start of parsing
        lines[0] = lines[0].replace("None", "Start")

        stack = []

        for line in lines:
            if line.strip() == "":
                continue

            splittedLine = line.split(" ")
            srcIP = splittedLine[0]

            if stack == []:
                ip = "Start"
            else:
                ip = stack.pop(-1)

            #Check ip is correct
            #print "dstip {} and srcip {}".format(ip, srcIP)
            assert srcIP in ip 
            
            srcIP = ip
    
            # if "None" in srcIP:
            #     srcIP = srcIP.replace("None", lastStar)
            if srcIP not in self.path:
                self.path[srcIP] = []

            tmpdst = []
            for i in range(1, len(splittedLine)):
                if '.' not in splittedLine[i] and "None" not in splittedLine[i]:
                    continue

                dstIP = splittedLine[i]

                # if "None" in dstIP:
                #     starCounter += 1

                # lastStar = "None{}".format(starCounter)
                # dstIP = dstIP.replace("None", lastStar)
                dstIP = dstIP.replace(",", "")
                
                number = 0
                if dstIP in counter:
                    number = counter[dstIP]
                    counter[dstIP] += 1
                else:
                    counter[dstIP] = number+1
                
                dstIP += "#{}".format(number)
                # if dstIP == srcIP.split("#")[0]:
                #     dstIP += "#{}".format(int(srcIP.split("#")[1])+1)
                # elif "." in dstIP:
                #     dstIP += "#0"
                
                tmpdst.append(dstIP)
                if dstIP not in self.path[srcIP]:
                    self.path[srcIP].append(dstIP)
                if dstIP not in self.path:
                    self.path[dstIP] = []
            stack.extend(tmpdst[::-1])
        
    def ParseMDA2(self, string):
        print ("Parsing mda paristraceroute")
        self.path = {}

        lines = string.split("\n")

        for line in lines:
            if 'lattice' in line.lower():
                lines = lines[lines.index(line)+1:]
                break

        lines[0] = lines[0].replace("None", "Start")

        starCounter = 0
        lastStar = ""
        previousSrc = []

        for line in lines:
            if line.strip() == "":
                continue

            splittedLine = line.split(" ")
            srcIP = splittedLine[0]

            for ip in previousSrc:
                if ip.split("#")[0] == srcIP:
                    srcIP = ip

            if srcIP in previousSrc:
                previousSrc.pop(previousSrc.index(srcIP))

            if "#" not in srcIP and '.' in srcIP:
                srcIP += "#0"
    
            if "None" in srcIP:
                srcIP = srcIP.replace("None", lastStar)
            if srcIP not in self.path:
                self.path[srcIP] = []

            for i in range(1, len(splittedLine)):
                if '.' not in splittedLine[i] and "None" not in splittedLine[i]:
                    continue

                dstIP = splittedLine[i]
                if "None" in dstIP:
                    starCounter += 1
                lastStar = "None{}".format(starCounter)
                dstIP = dstIP.replace("None", lastStar)
                dstIP = dstIP.replace(",", "")
                if dstIP == srcIP.split("#")[0]:
                    dstIP += "#{}".format(int(srcIP.split("#")[1])+1)
                elif "." in dstIP:
                    dstIP += "#0"
                
                if dstIP not in previousSrc:
                    previousSrc.append(dstIP)
                if dstIP not in self.path[srcIP]:
                    self.path[srcIP].append(dstIP)
                if dstIP not in self.path:
                    self.path[dstIP] = []

    def ContainSrcIP(self, ip):
        for key in self.path:
            if ip in key:
                return True
        return False
    
    def GetSrcIP(self, ip):
        ip = ip.strip()
        if ip == "":
            return None
        if "." not in ip and "None" not in ip:
            return None
        for key in self.path:
            if ip in key:
                return key
        return None

    def ContainIP(self, src, node):
        for ip in self.path[src]:
            if node in ip:
                return True
        return False

    def GetIP(self, src, node):
        for ip in self.path[src]:
            if node in ip:
                return ip
        return None

    def Visit(self, src, dst):
        #print self.path
        parents = {}
        queue = []
        visited = []
        queue.append(src)
        visited.append(src)
        parents[src] = None
        #print "Visit from {} to {}".format(src, dst)
        while queue != []:
            #print len(queue)
            src = queue.pop(0)
            
            for elem in self.path[src]:
                if elem not in visited:
                    visited.append(elem)
                    queue.append(elem)
                    parents[elem] = src
                    if elem == dst:
                        src = dst
                        break

        path = []
        ip = src

        while ip is not None:
            path.append(ip)
            ip = parents[ip]

        #Rem destination
        path = path[1:]
        #print "Visit end"
        return (path[::-1], src == dst)

    def EditDistance(self, hops):
        if self.algorithm == ParisTraceroute.EXHAUSTIVE:
            path = self.SimilarPath(hops)
            if len(path) < len(hops):
                path = path[:len(hops)]
            return Utils.EditDistance(path, hops)

        paths = self.GetPaths()
        mindist = sys.maxsize
        bestpath = []
        if paths == []:
            paths.append([])
        for path in paths:
            if len(path) < len(hops):
                path = path[:len(hops)]
            dist = Utils.EditDistance(path, hops)
            if dist < mindist:
                mindist = dist
                bestpath = path
        # print "\n\n"
        # print hops
        # print bestpath
        return mindist

    def RealEditDistance(self, hops):
        if self.ContainPath(hops):
            return 0
            
        if self.algorithm == ParisTraceroute.EXHAUSTIVE:
            path = self.SimilarPath(hops)
            return Utils.EditDistance(path, hops)

        paths = self.GetPaths()
        mindist = sys.maxsize
        bestpath = []
        if paths == []:
            paths.append([])
        for path in paths:
            dist = Utils.EditDistance(path, hops)
            if dist < mindist:
                mindist = dist
                bestpath = path
        # print "\n\n"
        # print hops
        # print bestpath
        return mindist

    def BestPath(self, hops):
        if self.algorithm == ParisTraceroute.EXHAUSTIVE:
            path = self.SimilarPath(hops)
            return path

        paths = self.GetPaths()
        mindist = sys.maxsize
        bestpath = []

        if paths == []:
            paths.append([])
        for path in paths:
            dist = Utils.EditDistance(path, hops)
            if dist < mindist:
                mindist = dist
                bestpath = path
        return bestpath
        
            
    def SimilarPath(self, hops):
        srcIP = "Start"
        path = []
        if srcIP not in self.path:
            return path

        for i in range(len(hops)):
            hop = hops[i]

            #print "Is '{}' inside {}?".format(hop, self.path[srcIP])
            ip = self.GetIP(srcIP, hop)
        
            
            if ip:
                srcIP = ip
                #print "Added {}".format(hop)
                path.append(hop)
            elif self.path[srcIP] == []:
                break
            elif "None" in self.path[srcIP][0] and hop == "":
                srcIP = self.path[srcIP][0]
                path.append("")
            elif "None" in self.path[srcIP][0]:
                path.append("")
            else:
                ip = self.GetSrcIP(hop)
                while i < len(hops)-1 and not ip and hop != "":
                    i += 1
                    hop = hops[i]
                    ip = self.GetSrcIP(hop)

                smallpath = []
                ok = False
                if not ip:
                    smallpath, ok = self.Visit(srcIP, "end")
                else:
                    smallpath, ok = self.Visit(srcIP, ip)
                if len(smallpath) > 0:
                    smallpath = smallpath[1:]
                    if len(smallpath) <= 0:
                        path.extend(smallpath)
                        return path
                    srcIP = smallpath[-1]
                    
                #print "Added {}".format(smallpath)
                path.extend(smallpath)
                if not ip or not ok:
                    break
                    
                srcIP = ip

        if self.path[srcIP] != []:
            smallpath, ok = self.Visit(srcIP, "end")
            path.extend(smallpath[1:])

        for i in range(len(path)):
            path[i] = path[i].split("#")[0]
            if "None" in path[i]:
                path[i] = ""
        #path = path[1:]
        return Utils.ClearIPs(path)

    def ContainPathPBP(self, hops):
        contains = True
        # print("ST: {}".format(hops))
        # print("PT: {}".format(self.path))
        for hop in hops:
            if hop == "" or "None" in hop:
                continue
            found = False
            for key in self.path:
                if hop in key:
                    found = True
                for ip in self.path[key]:
                    if hop in ip:
                        found = True
            if not found:
                contains = False
                #print("Different hop: {}".format(hop))
        return contains

    def ContainPath(self, hops):
        srcIP = "Start"

        if srcIP not in self.path:
            return False

        for i in range(len(hops)):
            hop = hops[i]

            #print "Is '{}' inside {}?".format(hop, self.path[srcIP])
            ip = self.GetIP(srcIP, hop)
            
            if ip:
                srcIP = ip
            elif self.path[srcIP] == []:
                return False
            elif "None" in self.path[srcIP][0] and hop == "":
                srcIP = self.path[srcIP][0]
            elif hop == "":
                while hop == "" and i < len(hops)-1:
                    i += 1
                    hop = hops[i]
                ip = self.GetSrcIP(hop)
                if not ip:
                    return False
                srcIP = ip
            else:
                return False
        return True
    
    def PathLength(self):
        srcIP = "Start"
        max_length = 0
        queue = []
        used_ip = []

        #print self.path

        if srcIP not in self.path:
            return 0

        queue.append({"hop":0, "ip":srcIP})
        used_ip.append(srcIP)

        while self.path[srcIP] != [] and len(queue) > 0:
            srcIP = queue[0]['ip']
            hop = queue[0]['hop']
            queue = queue[1:]
            used_ip = used_ip[1:]

            if "None" not in srcIP:
                max_length = max(max_length, hop)

            for elem in self.path[srcIP]:
                if elem not in used_ip:
                    queue.append({'hop': hop+1, 'ip': elem})
                    used_ip.append(elem)

        return max_length