import sys
import base64
from scapy.all import rdpcap, TCP, Raw

def solve(pcap_path):
    packets = rdpcap(pcap_path) #reading file
    selected_packets = [] #wanted packets

    for packet in packets:
        #it should be TCP and have Raw layer
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            tcp = packet[TCP] #getting TCP layer
            #only packets on port 4444
            if tcp.sport == 4444 or tcp.dport == 4444: 
                selected_packets.append(packet) #adding to list

    if len(selected_packets) == 0:
        print("No packets found on port 4444")
        return
    
    #since TCP packets can arrive out of order, we need to sort them by sequence number
    selected_packets.sort(key=lambda packet: packet[TCP].seq)

    payload = b""
    #take data from selected packets and add them in payload
    for packet in selected_packets:
        payload += packet[Raw].load

    print("Raw payload:", payload)

    start=payload.find(b"MSG:")
    end= payload.find(b":EOF")

    if start != -1 and end != -1:   
        encoded_data = payload[start + 4:end]
    else:
        encoded_data = payload
     
    #remove newlines, carriage returns and spaces from the encoded data
    encoded_data = encoded_data.replace(b"\n", b"").replace(b"\r", b"").replace(b" ", b"")
    
    #decoding the base64 encoded data to get the flag then returning it from bytes to a string
    flag = base64.b64decode(encoded_data).decode("utf-8") 
    print("flag:", flag)

if __name__ == "__main__":
    solve(sys.argv[1])