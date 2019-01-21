from netaddr import *
import pyasn

class Utils:
    Map = {}
    ASNDB = None

    @staticmethod
    def LoadMap(filename):
        f = None
        try:
            f = open(filename)
        except:
            return
        for line in f:
            if line.strip() == "" or '.' not in line:
                continue
            Utils.Map[line.split("-")[0]] = int(line.split("-")[1])
        f.close()

    @staticmethod
    def StoreMap(filename):
        f = open(filename, "w")
        for ip in Utils.Map:
            f.write("{}-{}\n".format(ip, Utils.Map[ip]))
        f.close()

    @staticmethod
    def StoreMapMissingIP(filename):
        f = open(filename, "w")
        for ip in Utils.Map:
            if Utils.Map[ip] < 0:
                f.write("{}\n".format(ip))
        f.close()

    @staticmethod
    def IsPublic(ip):
        if '.' not in ip:
            return True
        return not IPAddress(ip).is_private()
    @staticmethod
    def Intersection(a,b):
        c = []
        for e in a:
            if e in b:
                c.append(e)
        return c
    @staticmethod
    def AS(ip):
        if not Utils.ASNDB:
            Utils.ASNDB = pyasn.pyasn('asn.dat')

        if ip in Utils.Map:
            return Utils.Map[ip]

        try:
            asn = Utils.ASNDB.lookup(ip)[0]
        except:
            return -1

        if asn:
            Utils.Map[ip] = asn
            return asn
        return -1

        net_asn_url = 'https://stat.ripe.net/data/network-info/data.json'

        params = dict(
            resource=ip
        )
        resp = requests.get(url=net_asn_url, params=params)
        data = resp.json()  # Check the JSON Response Content documentation below
        if 'data' not in data.keys() or 'asns' not in data['data'].keys() or len(data['data']['asns']) == 0:
            Utils.Map[ip] = -1
            raise Exception("No proper entry in data " + str(data))
        Utils.Map[ip] = data['data']['asns'][0]
        return data['data']['asns'][0]

    @staticmethod
    def OriginAS(ips):
        srcip = ""
        dstip = ""
        # print("searching origin as")
        # print(ips)
        for ipstring in ips:
            if "." not in ipstring:
                continue
            if not IPAddress(ipstring).is_private():
                srcip = ipstring
                asn =  Utils.AS(srcip)
                if asn < 0:
                    continue
                # print(srcip)
                return asn
        return -1

    @staticmethod
    def IsPrivateIP(ip):
        return IPAddress(ip).is_private()

    @staticmethod
    def ClearIPs(ips):
        if ips == []:
            return ips

        count = 0
        reversed = ips[::-1]
        lastip = reversed[0]

        
        while count < len(reversed) and (reversed[count] == "" or reversed[count] == None):
            count += 1
            #print count

        if count > 0:
            return ips[:len(ips)-count]
        
        while count < len(reversed) and reversed[count] == lastip:
            count += 1

        if count > 0:
            return ips[:len(ips)-count+1]
        return ips
        
    @staticmethod
    def Converter(ips1, ips2):
        ips1 = Utils.ClearIPs(ips1)
        ips2 = Utils.ClearIPs(ips2)
        #print "Edit distance of: \n\t{}\n\t{}".format(ips1, ips2)
        start = ord(' ') + 1
        end = ord('~') + 1
        converter = {}
        converter['*'] = ' '
        actual_char = start

        ips1_converted = ""
        for ip in ips1:
            if ip == "" or "None" in ip:
                ip = "*"
            if ip not in converter:
                converter[ip] = chr(actual_char)
                actual_char += 1
                if actual_char > end:
                    raise Exception("Ended characters!")
            ips1_converted += converter[ip]
        
        ips2_converted = ""
        for ip in ips2:
            if ip == "" or "None" in ip:
                ip = "*"
            if ip not in converter:
                converter[ip] = chr(actual_char)
                actual_char += 1
                if actual_char > end:
                    raise Exception("Ended characters!")
            ips2_converted += converter[ip]

        return ips1_converted, ips2_converted

    @staticmethod
    def EditDistance3(ips1, ips2):
        ips1 = Utils.ClearIPs(ips1)
        ips2 = Utils.ClearIPs(ips2)
        ips1_len = min(len(ips1), len(ips2))
        ips1 = ips1[:ips1_len]

        #Old check
        ips1_str, ips2_str = Utils.Converter(ips1, ips2)
        return Utils.Levenshtein(ips1_str, ips2_str)

    @staticmethod
    #ips2 --> tracetcp
    def EditDistance(ips1, ips2):
        if ips2 == [] or ips1 == []:
            return max(len(ips1), len(ips2))
        ips1 = Utils.ClearIPs(ips1)
        ips2 = Utils.ClearIPs(ips2)
        # ips1_len = min(len(ips1), len(ips2))
        # ips1 = ips1[:ips1_len]

        #New check

        # ips1_index = 0
        # ips2_index = 0
        # errors = 0
        # while ips1_index < len(ips1) and ips2_index < len(ips2):
        #     if ips1[ips1_index] == ips2[ips2_index]:
        #         ips1_index += 1
        #         ips2_index += 1
        #     elif ips2[ips2_index] == "":
        #         ips1_index += 1
        #         ips2_index += 1
        #     elif ips1[ips1_index] == "" or "None" in ips1[ips1_index]:
        #         ips1_index += 1
        #         ips2_index += 1
        #         errors += 1
        #     else:
        #         skip = 0
        #         additionalerrors = 0
                
        #         #search if there is the same ip in the next hops
        #         #count how many diff it encounters
        #         #if it matches the same ip in the 'future': add all errors encountered and move the index
        #         #else add 1 error and move both of them
        #         for j in range(ips2_index, len(ips2)):
        #             if ips1[ips1_index] == ips2[j]:
        #                 errors += additionalerrors
        #                 ips2_index = j
        #                 break
        #             elif ips2[j] != "":
        #                 continue
        #             else:
        #                 additionalerrors += 1

        #         if ips1[ips1_index] != ips2[ips2_index]:
        #             errors += 1
        #             ips1_index += 1
        #             ips2_index += 1
        
        # errors += len(ips2) - ips2_index
            
        # return errors
        #Old check
        ips1_str, ips2_str = Utils.Converter(ips1, ips2)
        return Utils.Levenshtein(ips1_str, ips2_str)

    @staticmethod
    #ips2 --> tracetcp
    def EditDistance2(ips1, ips2):
        ips1_len = min(len(ips1), len(ips2))
        ips1 = ips1[:ips1_len]
        ips1_str, ips2_str = Utils.Converter(ips1, ips2)
        return Utils.Levenshtein(ips1_str, ips2_str)

    @staticmethod
    def Levenshtein(s1, s2):
        if len(s1) < len(s2):
            return Utils.Levenshtein(s2, s1)

        # len(s1) >= len(s2)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
                deletions = current_row[j] + 1       # than s2
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    @staticmethod
    def PathChanges2(ips1, ips2):
        ips1 = Utils.ClearIPs(ips1)
        ips2 = Utils.ClearIPs(ips2)
        changedHops = []
        samePath = True
        i=0
        j=0
        while i < len(ips1) and j < len(ips2):
            ip1 = ips1[i]
            ip2 = ips2[j]
            if ip1 == ip2:
                samePath = True
            elif samePath:
                changedHops.append(ip1)
                samePath = False
            j+=1
            i+=1
        if i < len(ips1):
            changedHops.append(ips1[i])
        elif j < len(ips2):
            changedHops.append(ips2[j])
        return changedHops


    @staticmethod
    def PathChanges(ips1, ips2):
        ips1 = Utils.ClearIPs(ips1)
        ips2 = Utils.ClearIPs(ips2)
        changedHops = []
        samePath = True
        i=0
        j=0
        while i < len(ips1) and j < len(ips2):
            ip1 = ips1[i]
            ip2 = ips2[j]
            if ip1 == ip2:
                samePath = True
            elif samePath and ip1 != "" and ip2 != "":
                hop = ip1
                if ip1 != "":
                    hop = ip2
                changedHops.append(hop)
                samePath = False
            j+=1
            i+=1
        if i < len(ips1):
            changedHops.append(Utils.NextNonEmptyHop(ips1, i))
        elif j < len(ips2):
            changedHops.append(Utils.NextNonEmptyHop(ips2, j))
        return changedHops

    @staticmethod
    def PrevNonEmptyHop(array, index):
        i = index - 1
        while i >= 0:
            if array[i] != "":
                return array[i]
            i -= 1
        return None
        
    @staticmethod
    def NextNonEmptyHop(array, index):
        for i in range(index, len(array)):
            if array[i] != "":
                return array[i]
        return None