'''
'
' Name:     Douglas Hon
' UvicID:   V00821840
' Date:     March 28, 2018
'
'''

from collections import OrderedDict
import dpkt 
import socket 
import sys

class RoundTripTime:
    def __init__(self, seq, ip, ts):
        self.seq = seq
        self.ip = ip
        self.ts = ts

def displaySrcIP(ip_src):
    print("The IP Address of the source node: %s" % ip_src)

def displayUltDstIP(ip_ult_dst):
    print("The IP Address of the ultimate destination node: %s" % ip_ult_dst)

def displayIntDstIP(ip_int_dst):
    print("The IP Address of the intermediate destination nodes: ")
    count = 1 
    for entry in ip_int_dst:
        print("        router %d: %s" % (count, entry))
        count += 1

def displayProtocols(protocols):
    print("The values in the protocol field of the IP headers:")
    for entry in protocols:
        print("        " + entry)

def displayRTT(time_recieved, time_sent, src_ip):
    averages = []
    rtt = []
    ips = []
    for e1 in time_recieved:
        for e2 in time_sent:
            if e1.seq == e2.seq:
                rtt.append(RoundTripTime(e1.seq, e1.ip, e1.ts-e2.ts))
    
    for entry in rtt:
        ips.append(entry.ip) 
    
    unique_ip = list(OrderedDict.fromkeys(ips))

    for thing in unique_ip:
        same_ip = []
        for trip in rtt:
            if trip.ip == thing:
                same_ip.append(trip.ts)
        result = sum(same_ip)/float(len(same_ip))
        averages.append(RoundTripTime(None, thing, result))
    
    for entry in averages:
        print("The average RTT between %s and %s is: %s," % (src_ip, entry.ip, entry.ts))

def main(argv):
    print("CSC361 Assingment 3")

    ip_src = None 
    ip_ult_dst = None
    ip_int_dst = []
    protocols = []
    time_sent = []
    time_recieved = []

    f = open(argv[1], "rb")
    pcap = dpkt.pcap.Reader(f)

    count = 0
    for ts, buf in pcap:
        count += 1
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        
        try:
            if ip.icmp != None:
                protocols.append("%d: ICMP" % ip.p)   
        except AttributeError:
            pass
        try:
            if ip.udp != None:
                protocols.append("%d: UDP" % ip.p)
        except AttributeError:
            pass

        try:
            src_host = socket.inet_ntoa(ip.src) 
            dst_host = socket.inet_ntoa(ip.dst) 

            if ip.ttl == 1 and ip_src == None and ip_ult_dst == None:
                ip_src = src_host
                ip_ult_dst = dst_host
                # Print output to console
                displaySrcIP(src_host)
                displayUltDstIP(dst_host)

            if ip_src == src_host and ip_ult_dst == dst_host:
                time_sent.append(RoundTripTime(tcp.data.seq.numerator, None, ts))

            if tcp.type == 11:
                ip_int_dst.append(src_host)
                time_recieved.append(RoundTripTime(tcp.data.ip.icmp.data.seq.numerator, src_host, ts))
        except (AttributeError, OSError) as e:
            continue

    # Removes duplicate IP's from the list while still maintaining the order
    ip_int_dst = list(OrderedDict.fromkeys(ip_int_dst))
    # Print output to console
    displayIntDstIP(ip_int_dst)

    # Removes duplicate protocols from the list
    protocols = list(OrderedDict.fromkeys(protocols))
    # Prints the used protocols to the console
    displayProtocols(protocols)

    displayRTT(time_recieved, time_sent, src_host)

    
'''
        try:
            try:
                src_host = socket.inet_ntoa(ip.src) 
                dst_host = socket.inet_ntoa(ip.dst) 

                if ip.ttl == 1:
                    srcIP(src_host)
                    ultDstIP(dst_host)

                print(dir(tcp))
                print(tcp.type)

                #print("%d. src: %s, dst: %s, ttl: %s, seq: %d" % (count, src_host, dst_host, ip.ttl, tcp.data.seq))
                #print(tcp.data.pack)
            except OSError:
                print("IP not in correct format")
                count += 1
                continue
        except AttributeError:
            print("Doesn't have the source attribute")
            count += 1
            continue
#        print(ip.udp);
        count += 1
'''

if __name__ == "__main__":
    main(sys.argv)
