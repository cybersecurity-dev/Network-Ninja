import scapy.all as scapy
import matplotlib.pyplot as plt
from collections import defaultdict
import datetime
import pandas as pd
import sys
import os

def process_packets(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    
    data = defaultdict(lambda: {"incoming": defaultdict(int), "outgoing": defaultdict(int)})
    unique_ips = set()
    
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            
            # Convert packet time to float
            timestamp = float(packet.time)
            timestamp = datetime.datetime.fromtimestamp(timestamp)
            hour_minute = timestamp.replace(second=0, microsecond=0)
            packet_len = len(packet)
            
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Add IPs to the unique IPs set
            unique_ips.add(src_ip)
            unique_ips.add(dst_ip)
            
            # Aggregate outgoing bytes for the source IP
            data[src_ip]["outgoing"][hour_minute] += packet_len
            
            # Aggregate incoming bytes for the destination IP
            data[dst_ip]["incoming"][hour_minute] += packet_len
    
    return data, unique_ips

def plot_data(data, ip):
    incoming_data = data[ip]["incoming"]
    outgoing_data = data[ip]["outgoing"]
    
    times = sorted(set(incoming_data.keys()).union(outgoing_data.keys()))
    
    incoming_bytes = [incoming_data[time] for time in times]
    outgoing_bytes = [outgoing_data[time] for time in times]
    
    plt.figure(figsize=(12, 6))
    plt.plot(times, incoming_bytes, label="Incoming Bytes", color="blue")
    plt.plot(times, outgoing_bytes, label="Outgoing Bytes", color="red")
    
    plt.xlabel("Time")
    plt.ylabel("Bytes")
    plt.title(f"Incoming/Outgoing Bytes Over Time for {ip}")
    plt.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def save_to_csv(data, ip):
    incoming_data = data[ip]["incoming"]
    outgoing_data = data[ip]["outgoing"]
    
    times = sorted(set(incoming_data.keys()).union(outgoing_data.keys()))
    
    rows = []
    for time in times:
        row = {
            "Time": time,
            "Incoming Bytes": incoming_data[time],
            "Outgoing Bytes": outgoing_data[time]
        }
        rows.append(row)
    
    df = pd.DataFrame(rows)
    csv_filename = f"{ip}_traffic.csv"
    df.to_csv(csv_filename, index=False)
    print(f"Data saved to {csv_filename}")


def main(pcap_file):
    data, unique_ips = process_packets(pcap_file)
    print("Unique IPs found in the pcap file:")
    for ip in unique_ips:
        print(ip)
    
    ip_to_plot = input("Enter the IP you want to plot: ")
    
    if ip_to_plot in data:
        plot_data(data, ip_to_plot)
        save_to_csv(data, ip_to_plot)
    else:
        print(f"No data found for IP: {ip_to_plot}")

if __name__ == "__main__":
  # Check if a parameter is provided
  if len(sys.argv) == 2 :
    pcap_file = sys.argv[1] 
    if os.path.exists(pcap_file):
       main(pcap_file)
    else:
        print(f"File '{pcap_file}' does not exist.")    
  else:
    print("No pcap file provided.")