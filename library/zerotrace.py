from library.utils import *

import json
class Zerotrace:
    def __init__(self, json, verbose):
        self.targetIP = ""
        self.targetPort = ""
        self.localPort = ""
        self.interface = ""
        self.error = ""
        self.hops = []
        self.verbose = verbose

        self.Read(json)

    def Read(self, json):
        self.targetIP = json['ip']
        self.targetPort = json['port']
        self.interface = json['iface']
        self.error = json['error']
        self.Parse(json)

    def Parse(self, json):
        output = json['output'].split("\n")
        #Line 1: Presentation
        #Line 2: Waiting traffic
        #Line 3: Waiting a gap
        #Line 4: Target acquired --> get port
        self.localPort = int(output[3].split(" ")[3].split(":")[1])
        #Line 5: Setting sniffer
        #Line 6: Sending probes
        #Line 7: Empty, just formatting
        #Line 8: Title
        #Line 9: Divider, just formatting
        #Line 10: Results!!!
        for i in range(9, len(output)):
            res = output[i].split(" ")
            if len(res) != 2 or "Probe" in output[i] or "Target" in output[i]:
                break
            index = int(res[0])
            if index-1 >= len(self.hops):
                self.hops.extend([""]*(index-1-len(self.hops)))
            self.hops.append(res[1])


    def RealEditDistance(self, hops):
        return Utils.EditDistance(self.hops, hops)

    def EditDistance(self, hops):
        copy = self.hops
        if len(hops) < len(self.hops):
            copy = copy[:len(hops)]
        return Utils.EditDistance(copy, hops)
            

    @staticmethod
    def LoadZeroTraces(filename, verbose):
        print ("\tLoading {}".format(filename))

        f = open(filename)

        zts = json.load(f)

        f.close()

        zerotraces = []
        for zt in zts:
            zero = Zerotrace(zt,verbose)
            if verbose:
                print("Zerotrace to {}:{} --> {}:{} on interface {}".format(zero.localPort, zero.localPort, zero.targetIP, zero.targetPort, zero.interface))
                for i in range(len(zero.hops)):
                    print("{} {}".format(i+1, zero.hops[i]))
                print("Errors: {}".format(zero.error))
            zerotraces.append(zero)
        
        print ("Loaded!")
        return zerotraces


if __name__ == "__main__":
    filename = "/Users/ivanmorandi/results/results/atrain.d32.i3.ip100.ptcp.youtube.it=0.0.zt.log"
    Zerotrace.LoadZeroTraces(filename, True)