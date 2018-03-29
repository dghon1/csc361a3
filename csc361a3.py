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

protocols = ([])

def displaySrcIP(ip_src):
    print("IP Address of the source node: %s" % ip_src)

def displayUltDstIP(ip_ult_dst):
    print("IP Address of the ultimate destination node: %s" % ip_ult_dst)

def displayIntDstIP(ip_int_dst):
    print("IP Address of the intermediate destination nodes: ")
    count = 1 
    for entry in ip_int_dst:
        print("    router %d: %s" % (count, entry))
        count += 1

def main(argv):
    print("CSC361 Assingment 3")

    ip_src = None 
    ip_ult_dst = None
    ip_int_dst = []

    f = open(argv[1], "rb")
    pcap = dpkt.pcap.Reader(f)

    count = 1
    for ts, buf in pcap:
        if count == 50:
            break

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        
        try:
            src_host = socket.inet_ntoa(ip.src) 
            dst_host = socket.inet_ntoa(ip.dst) 

            if tcp.type == 8:
                if ip.ttl == 1 and ip_src == None and ip_ult_dst == None:
                    ip_src = src_host
                    ip_ult_dst = dst_host
                    # Print output to console
                    displaySrcIP(src_host)
                    displayUltDstIP(dst_host)
            elif tcp.type == 11:
                ip_int_dst.append(src_host)
        except (AttributeError, OSError) as e:
            continue
    # Removes duplicate IP's from the list while still maintaining the order
    ip_int_dst = list(OrderedDict.fromkeys(ip_int_dst))
    # Print output to console
    displayIntDstIP(ip_int_dst)

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
