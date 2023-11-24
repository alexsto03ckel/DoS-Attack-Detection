import netifaces
import winreg
import csv
import os
from scapy.all import sniff, IP, IPv6, TCP, UDP
from scapy.arch import windows

def int_names(int_guids):
    int_names = ['(unknown)' for _ in range(len(int_guids))]
    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    reg_key = winreg.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i, int_guid in enumerate(int_guids):
        try:
            reg_subkey = winreg.OpenKey(reg_key, int_guid + r'\Connection')
            int_names[i] = winreg.QueryValueEx(reg_subkey, 'Name')[0]
        except FileNotFoundError:
            pass
    return int_names

def display_interface_options():
    interfaces = windows.get_windows_if_list()
    print("Available network interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i}. {interface['name']}")

    while True:
        try:
            selected_index = int(input("Enter the number of the interface you want to capture packets from: "))
            if 0 <= selected_index < len(interfaces):
                selected_interface = interfaces[selected_index]['name']
                return selected_interface
            else:
                print("Invalid selection. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def start_capture(interface):
    def calculate_fwd_seg_size(pkt):
        try:
            return len(pkt.payload)
        except Exception:
            return 0
        
    def extract_init_fwd_win_bytes(pkt):
        try:
            if IP in pkt:
                if TCP in pkt:
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
                elif UDP in pkt:
                    # Adjust this part based on the specific information you want to extract for UDP
                    return pkt[UDP].sport  # For example, using the source port for simplicity
        except Exception as e:
            print(f"Error processing packet: {e}")

        return 0



    def extract_fwd_seg_size_min(pkt):
        if pkt.haslayer(TCP):
            payload_size = len(pkt[TCP].payload)
            return payload_size
        elif pkt.haslayer(UDP):  # Add UDP packet processing
            payload_size = len(pkt[UDP].payload)
            return payload_size
        return 0

    fwd_pkt_count = 0

    def csvgather(pkt):
        if pkt.haslayer(IP):
            ip = pkt[IP].dst
            try:
                fieldnames = ["Src Port", "Dst Port", "TotLen Fwd Pkts", "Fwd Pkt Len Mean", "Init Fwd Win Byts", "Fwd Seg Size Min"]

                with open('test5.csv', 'a', newline='') as csvfile:
                    file_empty = os.stat('test5.csv').st_size == 0 

                    filewriter = csv.DictWriter(csvfile, fieldnames=fieldnames)

                    if file_empty:
                        filewriter.writeheader()

                    print(ip)
                    fwd_seg_size_min = extract_fwd_seg_size_min(pkt)
                    fwd_seg_size = calculate_fwd_seg_size(pkt)

                    init_fwd_win_bytes = 0
                    if TCP in pkt:
                        init_fwd_win_bytes = extract_init_fwd_win_bytes(pkt)
                    elif UDP in pkt:
                        init_fwd_win_bytes = extract_init_fwd_win_bytes(pkt)

                    src_port = getattr(pkt[TCP], 'sport', 0) if TCP in pkt else getattr(pkt[UDP], 'sport', 0)
                    dst_port = getattr(pkt[TCP], 'dport', 0) if TCP in pkt else getattr(pkt[UDP], 'dport', 0)

                    pkt_len = pkt.len if hasattr(pkt, 'len') else 0
                    fwd_pkt_len_sum = getattr(csvgather, 'fwd_pkt_len_sum', 0)
                    fwd_pkt_count = getattr(csvgather, 'fwd_pkt_count', 0)
                    fwd_pkt_len_sum += pkt_len
                    fwd_pkt_count += 1
                    fwd_pkt_len_mean = fwd_pkt_len_sum / fwd_pkt_count if fwd_pkt_count > 0 else 0

                    setattr(csvgather, 'fwd_pkt_len_sum', fwd_pkt_len_sum)
                    setattr(csvgather, 'fwd_pkt_count', fwd_pkt_count)

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


    for i in range(1, 10):
        cap = sniff(count=100, prn=csvgather, iface=interface)
        fwd_pkt_count = 0

if __name__ == "__main__":
    selected_interface = display_interface_options()
    print(f"Selected interface: {selected_interface}")
    start_capture(selected_interface)
