from . import utils
from analyser.utils import *
from analyser.protocols.ssdp import ssdp_analysis
from analyser.protocols.mdns import mdns_analysis
from analyser.protocols.ipv6 import ipv6_analysis
from analyser.protocols.http import http_analysis
from analyser.protocols.tplinksmarthome import tplink_smarthome_analysis
from analyser.protocols.classicstun import classicstun_analysis
from analyser.protocols.dhcp import dhcp_analysis
from analyser.protocols.icmp import icmp_analysis
from analyser.protocols.arp import arp_analysis
from analyser.protocols.mc import MC_analysis



"""
Protocol-wise analysis 
inputs: 
    out_dir: output directory
    dict_dec: a dictionary with device names as keys and pcap files as values
    packets_dict: a dictionary of pyshark-processed packets, keys are the device name and values are packets
return:
    (header, return_list)
"""



    
# TODO integrate the cert extraction script to this 
def extract_tls_cert(capture):
    count = 0
    for packet in capture:
        ca_count = analyzePacket(packet, ca_count)
        count += 1
    print('%s: %d' %(count))
    capture.close()
    return count 

# TODO
def tls_analysis():

    return 0 

def udp_analysis():
    return 0

def llc_analysis(out_dir, dict_dec, packets_dict):
    
    return 0 

def protocols_analysis_pyshark(out_dir, dict_dec, all_packets_captures, pcap_filter):
    match pcap_filter.lower():
        case 'dhcp': 
            return dhcp_analysis(out_dir, dict_dec, all_packets_captures)
        case 'arp':
            return arp_analysis(out_dir, dict_dec, all_packets_captures)
        case 'icmp':
            return icmp_analysis(out_dir, dict_dec, all_packets_captures)
        case 'ssdp':
            return ssdp_analysis(out_dir, dict_dec, all_packets_captures)
        case 'llc':
            return llc_analysis(out_dir, dict_dec, all_packets_captures)
        case 'tplink-smarthome': 
            return tplink_smarthome_analysis(out_dir, dict_dec, all_packets_captures)
        case 'classicstun':
            return classicstun_analysis(out_dir, dict_dec, all_packets_captures)
        case 'multicast':
            return MC_analysis(out_dir, dict_dec, all_packets_captures)
        case 'http': 
            return http_analysis(out_dir, dict_dec, all_packets_captures)
        case 'tls': # TODO
            return tls_analysis(out_dir, dict_dec, all_packets_captures)
        case 'ipv6':
            return ipv6_analysis(out_dir, dict_dec, all_packets_captures)
        case 'mdns':
            return mdns_analysis(out_dir, dict_dec, all_packets_captures)
        case 'udp': # TODO
            return udp_analysis(out_dir, dict_dec, all_packets_captures)
        case _:
            print('Unrecognized protocol: ', pcap_filter)
            return 0 


def protocols_analysis_tshark(out_dir, dict_dec, all_packets, pcap_filter):
    for protocol in pcap_filter:
        print(protocol)
    feature_header = ['number', 'time_epoch', 'time_delta', 'len (size)', 'src mac', 'dst mac', 'Protocol', 'layer 4 protocol code (optional)', 
                    'TCP/UDP stream (optional)', 'src ip (optional)', 'dst ip (optional)', 'src port (optional)', 'dst port (optional)']
    cur_out_dir = os.path.join(out_dir, 'low_volume_traffic')
    if not os.path.exists(cur_out_dir):
        os.system('mkdir -pv %s' % cur_out_dir)
    for device in dict_dec:
        protocols_out_file = os.path.join(cur_out_dir, '%s.csv' % device)
        cur_all_packets = all_packets[device]['packets'] 
        with open(protocols_out_file, 'w') as f:
            write = csv.writer(f)
            write.writerow(feature_header)
            write.writerows(cur_all_packets)
        # write.writerow(overall_result)
    
    
    return 0 