import csv
import os
from scapy.all import sniff, IP, IPv6, ARP, TCP, UDP


def calculate_fwd_seg_size(pkt):
    try:
        return len(pkt.payload)
    except Exception:
        return 0
    
def extract_init_fwd_win_bytes(pkt):
    if pkt.haslayer(TCP):
        tcp_flags = pkt[TCP].flags
        if 'W' in tcp_flags:  # Check if Window Scale option is present
            tcp_options_raw = pkt[TCP].options
            for opt_type, opt_value in tcp_options_raw:
                if opt_type == 'WScale':
                    # Extract the scale factor from the option value
                    scale_factor = opt_value
                    return pkt[TCP].window << scale_factor
        else:
            # If Window Scale option is not present, use the window size directly
            return pkt[TCP].window
    
    return 0

def extract_fwd_seg_size_min(pkt):
    if pkt.haslayer(TCP):
        payload_size = len(pkt[TCP].payload)
        return payload_size
    return 0

fwd_pkt_count = 0

def csvgather(pkt):
        if(pkt.haslayer(IP)):
            ip = pkt[IP].dst
            #if(ip == '13.248.243.5' or ip == '76.223.105.230'):
            try:
                    fieldnames = ["Src Port", "Dst Port", "TotLen Fwd Pkts", "Fwd Pkt Len Mean", "Init Fwd Win Byts", "Fwd Seg Size Min"]

                    with open('DataSample3.csv', 'a', newline='') as csvfile:
                        file_empty = os.stat('DataSample3.csv').st_size == 0  # Check if the file is empty

                        filewriter = csv.DictWriter(csvfile, fieldnames=fieldnames)

                        if file_empty:
                            filewriter.writeheader()
                        print(ip)
                        fwd_seg_size_min = extract_fwd_seg_size_min(pkt)
                        fwd_seg_size = calculate_fwd_seg_size(pkt)
                        init_fwd_win_bytes = extract_init_fwd_win_bytes(pkt)
                        src_port =pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        
                        # Calculate Fwd Pkt Len Mean
                        pkt_len = pkt.len if hasattr(pkt, 'len') else 0
                        fwd_pkt_len_sum = getattr(csvgather, 'fwd_pkt_len_sum', 0)
                        fwd_pkt_count = getattr(csvgather, 'fwd_pkt_count', 0)
                        fwd_pkt_len_sum += pkt_len
                        fwd_pkt_count += 1
                        fwd_pkt_len_mean = fwd_pkt_len_sum / fwd_pkt_count if fwd_pkt_count > 0 else 0

                        setattr(csvgather, 'fwd_pkt_len_sum', fwd_pkt_len_sum)
                        setattr(csvgather, 'fwd_pkt_count', fwd_pkt_count)

                        #Calculate TotLen Fwd Pkts
                        totlen_fwd_pkts = getattr(csvgather, 'totlen_fwd_pkts', 0)
                        totlen_fwd_pkts = pkt_len
                        setattr(csvgather, 'totlen_fwd_pkts', totlen_fwd_pkts)

                        filewriter.writerow({
                            'Src Port': src_port,
                            'Dst Port': dst_port,
                            'TotLen Fwd Pkts': totlen_fwd_pkts,
                            'Fwd Pkt Len Mean': fwd_pkt_len_mean,
                            'Init Fwd Win Byts': init_fwd_win_bytes,                            
                            'Fwd Seg Size Min': fwd_seg_size_min,
                        })

            except Exception as e:
                    print(f"Error processing packet: {e}")

for i in range (1,10):
    cap = sniff(count=100, prn=csvgather)
    fwd_pkt_count = 0

