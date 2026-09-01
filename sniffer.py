from scapy.all import * 
from datetime import datetime

packet_log = open("logs/Sniffer_log.txt","a")

def handle_packet(packet):
    if packet.haslayer(IP):
        source_ip = packet.getlayer(IP).src
        destination_ip = packet.getlayer(IP).dst
        info = "Source : " + source_ip + "=> Destination : " + destination_ip

        if packet.haslayer(TCP):
            source_port = packet.getlayer(TCP).sport
            destination_port = packet.getlayer(TCP).dport
            info = info + " | Protocol: TCP Ports : " + str(source_port) + "=> " + str(destination_port)

        elif packet.haslayer(UDP):
            source_port = packet.getlayer(UDP).sport
            destination_port = packet.getlayer(UDP).dport
            info = info + " | Protocol : UDP Ports : " + str(source_port) + "=> " + str(destination_port)

        elif packet.haslayer(ICMP):
            info = info + "| Protocol : ICMP "

        else :
            info = info + "| Other Protocols"


        if packet.haslayer(Raw):
            payload_bytes = packet.getlayer(Raw).load
            info = info + "| Payload : " + str(payload_bytes[:40])


        current_time = datetime.now().strftime("%Y-%m-%d %H%M%S")
        final_line = current_time + " - " + info

        print(final_line)

        packet_log.write(final_line+"\n")
        packet_log.flush()



pck_iface = input("Enter network interface name : ")
pack_count = int(input("Enter packet count : "))
sniff(prn=handle_packet,count=pack_count,iface=pck_iface)
packet_log.close()
