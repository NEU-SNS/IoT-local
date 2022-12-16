from . import utils
from analyser.utils import *
import datetime
import re
# from analyser.protocols.dhcp import dhcp_analysis
# from analyser.protocols.arp import arp_analysis

# TODO
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



"""
Protocol-wise analysis 
inputs: 
    out_dir: output directory
    dict_dec: a dictionary with device names as keys and pcap files as values
    packets_dict: a dictionary of pyshark-processed packets, keys are the device name and values are packets
return:
    (header, return_list)
"""


def MC_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','multicast')
    nodes_address_count = {}
    router_address_count = {}
    address_group_count = {}
    wrong_group_count = {}
    
    for device in dict_dec:
        print('analyzing Multicast packets...', device)
        if device not in packets_dict:
            # nodes_address_count[device] = 0
            # router_address_count[device] = 0
            # address_group_count[device] = set()
            continue
        address_group_dict = {}
        for packet in packets_dict[device]:
            # All Nodes Address
            if packet.eth.dst.split(':')[-1] == '1' or packet.eth.dst.split(':')[-1] == '01':
                # print('Nodes address')
                nodes_address_count[device] = nodes_address_count.get(device, 0) + 1

            # All Routers Address
            if packet.eth.dst.split(':')[-1] == '2' or packet.eth.dst.split(':')[-1] == '02':
                # print('Router address')
                router_address_count[device] = router_address_count.get(device, 0) + 1
            if device in address_group_count:
                address_group_count[device].add(packet.eth.dst)
            else:
                address_group_count[device] = set([packet.eth.dst])
                
            address_group_dict[packet.eth.dst] = address_group_dict.get(packet.eth.dst, 0) + 1

            top_layer_name = packet.layers[-1].layer_name
            if top_layer_name=='mdns':
                wrong_group_count[device] = wrong_group_count.get(device, 0) + mdns_packet_analysis(packet)
            elif top_layer_name=='dhcpv6':
                wrong_group_count[device] = wrong_group_count.get(device, 0) + dhcpv6_analysis(packet)
            # if top_layer_name=='igmp':
            #     IGMP_analysis(packet)


        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            sorted_address_group_dict = sorted([(k,v) for k,v in address_group_dict.items()], key=lambda t:t[1], reverse=True)
            
            for i in sorted_address_group_dict:
                f.write('%s: %d\n' % (i[0], i[1]))
            
    # nodes_address_count_all = 0
    # router_address_count_all = 0
    # address_group_count_all = set()
    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, nodes_address_count.get(device, 0), router_address_count.get(device, 0), len(address_group_count.get(device, set())), wrong_group_count.get(device, 0))
        # if (bind_request_count.get(device, 0) + share_request_count.get(device, 0) + other_count.get(device, 0)) == 0:
        #         continue
        return_list.append([device, nodes_address_count.get(device, 0), router_address_count.get(device, 0), len(address_group_count.get(device, set())), wrong_group_count.get(device, 0)])

    header = ['device', 'nodes_address_count', 'router_address_count', 'address_group_count', 'wrong_group_count']
    return (header, return_list)

# def IGMP_analysis(packet):
#     if packet.ip.dst.split('.')[-1] != '22':
#         print('Wrong IGMP multicast group')


def mdns_packet_analysis(packet):
    if packet.eth.dst.split(':')[-1] != 'fb':
        print('Wrong MDNS multicast group')
        return 1
    else:
        return 0


def mdns_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','mdns')
    v4_count = {}
    v6_count = {}
    query_count = {}
    response_count = {}
    unique_query_count = {}
    unique_response_count = {}
    
    for device in dict_dec:
        print('analyzing MDNS packets...', device) # os.getpid()
        if device not in packets_dict:
            continue
        
        query_records = {}
        response_records = {}
        type_dict = {'1':'A', '2':'NS', '5':'CNAME', '12':'PTR','16':'TXT', '28':'AAAA', '33':'SRV', '255':'ANY'}
        for packet in packets_dict[device]:
            # print(packet)

            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            # print(src_mac, dst_mac)
            if dst_mac.startswith('33:33'):
                v6_count[device] = v6_count.get(device, 0) + 1
            else:
                v4_count[device] = v4_count.get(device, 0) + 1
            
            
            if packet.mdns.dns_flags_response == '0':
                query_count[device] = query_count.get(device, 0) + 1
                
                
                # resp_addr = packet.mdns.dns_a
                
                if int(packet.mdns.dns_count_queries) > 1:
                    for line in packet.mdns._get_all_field_lines():
                        # if line.strip().startswith('Name:'):
                        if re.match('(.*)(: type)(.*)(, class)(.*)', line) != None:
                            # print(line.strip())
                            qry_name = line.strip().split(':')[0].strip()
                            qry_type = line.strip().split(':')[1].split(',')[0].strip().split(' ')[1]
                            query_records[(qry_name, qry_type)] = query_records.get((qry_name, qry_type), 0) + 1
                            
                else:
                    qry_name = packet.mdns.dns_qry_name
                    qry_type = packet.mdns.dns_qry_type
                    if qry_type in type_dict:
                        qry_type = type_dict[qry_type]
                    query_records[(qry_name, qry_type)] = query_records.get((qry_name, qry_type), 0) + 1
                        
                
            else:
                response_count[device] = response_count.get(device, 0) + 1
                
                
                # if int(packet.mdns.dns_count_answers) > 1:
                for line in packet.mdns._get_all_field_lines():
                    # if line.strip().startswith('Name:'):
                    if re.match('(.*)(: type)(.*)(, class)(.*)', line) != None:
                        resp_name = line.strip().split(':')[0].strip()
                        try:
                            resp_type = line.strip().split(': ')[1].split(',')[0].strip().split(' ')[1]
                        except: 
                            print(line)
                            exit(1)
                        resp_addr = line.strip().split()[-1]
                        response_records[(resp_name, resp_type, resp_addr)] = response_records.get((resp_name, resp_type, resp_addr), 0) + 1
                # else:
                #     resp_name = packet.mdns.dns_resp_name
                #     resp_type = packet.mdns.dns_resp_type
                #     if resp_type == '1':
                #         resp_addr = packet.mdns.dns_a
                #     elif resp_type == '28':
                #         resp_addr = packet.mdns.dns_aaaa
                #     else:
                #         resp_addr = ' '
                    
                #     if resp_type in type_dict:
                #         resp_type = type_dict[resp_type]
                #     response_records[(resp_name, resp_type, resp_addr)] = response_records.get((resp_name, resp_type, resp_addr), 0) + 1
                
                
                
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        unique_query_count[device] = len(query_records)
        unique_response_count[device] = len(response_records)
        with open(out_file, 'w') as f:
            # sorted_query_records = sorted([(k,v) for k,v in query_records.items()], key=lambda t:t[1], reverse=True)
            f.write('Query: %d\n' % len(query_records))
            for i in query_records:
                f.write('%s: %d\n' % (i, query_records[i]))    
            
            # sorted_query_records = sorted([(k,v) for k,v in query_records.items()], key=lambda t:t[1], reverse=True)
            f.write('\n\nResponse: %d\n' % len(response_records))
            for i in response_records:
                f.write('%s: %d\n' % (i, response_records[i]))   
            
    return_list = []
    for device in dict_dec:
        # count += 1
        print(device, v4_count.get(device, 0), v6_count.get(device, 0), query_count.get(device, 0), response_count.get(device, 0))
        return_list.append([device, v4_count.get(device, 0), v6_count.get(device, 0), query_count.get(device, 0),  unique_query_count.get(device, 0), response_count.get(device, 0), unique_response_count.get(device, 0)])
    header = ['device', 'v4_count', 'v6_count',  'query_count', 'unique_query_count', 'response_count', 'unique_response_count']
    return (header, return_list) 

    
def ipv6_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','ipv6')
    dhcpv6_count = {}
    icmpv6_count = {}
    other_count = {}
    # wrong_group_count = {}
    
    for device in dict_dec:
        print('analyzing IPv6 packets...', device)
        if device not in packets_dict:
            # nodes_address_count[device] = 0
            # router_address_count[device] = 0
            # address_group_count[device] = set()
            continue
        # address_group_dict = {}
        device_protocol_count = {}
        for packet in packets_dict[device]:
            
            # if device in address_group_count:
            #     address_group_count[device].add(packet.eth.dst)
            # else:
            #     address_group_count[device] = set([packet.eth.dst])
                
            # address_group_dict[packet.eth.dst] = address_group_dict.get(packet.eth.dst, 0) + 1

            top_layer_name = packet.layers[-1].layer_name
            if str(top_layer_name).lower()=='dhcpv6':
                dhcpv6_count[device] = dhcpv6_count.get(device, 0) + 1
                device_protocol_count['dhcpv6'] = device_protocol_count.get('dhcpv6', 0) + 1
            elif str(top_layer_name).lower()=='icmpv6':
                icmpv6_count[device] = icmpv6_count.get(device, 0) + 1
                device_protocol_count['icmpv6'] = device_protocol_count.get('icmpv6', 0) + 1
            else:
                other_count[device] = other_count.get(device, 0) + 1
                
                device_protocol_count[str(top_layer_name).lower()] = device_protocol_count.get(str(top_layer_name).lower(), 0) + 1



        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            sorted_device_protocol_count = sorted([(k,v) for k,v in device_protocol_count.items()], key=lambda t:t[1], reverse=True)
            
            for i in sorted_device_protocol_count:
                f.write('%s: %d\n' % (i[0], i[1]))
            
    # nodes_address_count_all = 0
    # router_address_count_all = 0
    # address_group_count_all = set()
    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, dhcpv6_count.get(device, 0), icmpv6_count.get(device, 0), other_count.get(device, 0))
        # if (bind_request_count.get(device, 0) + share_request_count.get(device, 0) + other_count.get(device, 0)) == 0:
        #         continue
        return_list.append([device, dhcpv6_count.get(device, 0), icmpv6_count.get(device, 0), other_count.get(device, 0)])

    header = ['device', 'dhcpv6_count', 'icmpv6_count',  'other_count']
    return (header, return_list)


def dhcpv6_analysis(packet):
    if packet.eth.dst.split(':')[-1] != '3' or packet.eth.dst.split(':')[-2] != '1':
        # print('Wrong DHCPv6 multicast group')
        return 1
    else:
        return 0
    

def icmpv6_analysis():
    return 0

def http_analysis():
    return 0

def udp_analysis():
    return 0

def llc_analysis(out_dir, dict_dec, packets_dict):
    
    return 0 

def tplink_smarthome_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','tplink-smarthome')
    
    mac_dic = read_mac_address()
    rev_mac_dict = {}
    for k,v in mac_dic.items():
        rev_mac_dict[v] = k
    
    get_sysinfo_count = {}
    other_count = {}
    udp_count = {}
    tcp_count = {}
    cmd_count = {}
    rsp_count = {}
    for device in dict_dec:
        print('analyzing classic-stun packets...', device) # os.getpid()
        if device not in packets_dict:
            continue
        
        
        message = {}
        sent_tcp = 0
        sent_udp = 0
        sent_udp_broadcast = 0
        received_tcp = 0
        received_udp = 0
        count = 0
        for packet in packets_dict[device]:
            # print(packet.classicstun)
            # exit(1)
            my_device_mac = mac_dic[device]
            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            
            transport_layer_protocol = packet.ip.proto
            if transport_layer_protocol == '17':
                udp_count[device] = udp_count.get(device, 0) + 1
                
                if src_mac == my_device_mac:
                    sent_udp += 1
                    if is_broadcast(dst_mac):
                        sent_udp_broadcast += 1
                else:
                    received_udp += 1
            elif transport_layer_protocol == '6':
                tcp_count[device] = tcp_count.get(device, 0) + 1
                if src_mac == my_device_mac:
                    sent_tcp += 1
                else:
                    received_tcp += 1
                    
            else:
                # ICMP
                continue
            
            

            json_path = packet['tplink-smarthome'].json_path
            
            if len(json_path.split('/')) > 3:
                cur_command = json_path.split('/')[2]
                rsp_count[device] = rsp_count.get(device, 0) + 1

            elif len(json_path.split('/')) == 3:
                cur_command = json_path.split('/')[2]
                cmd_count[device] = cmd_count.get(device, 0) + 1
                
            else:
                cur_command = json_path

                
            if 'get_sysinfo' in cur_command:
                get_sysinfo_count[device] = get_sysinfo_count.get(device, 0) + 1
            else:
                other_count[device] = other_count.get(device, 0) + 1
                message[cur_command] = message.get(cur_command, 0) + 1

        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            f.write('Sent TCP: %d\n' % (sent_tcp))
            f.write('Sent UDP: %d\n' % (sent_udp))
            f.write('Sent UDP Broadcast: %d\n' % sent_udp_broadcast)
            f.write('Received TCP: %d\n' % (received_tcp))
            f.write('Received UDP: %d\n' % (received_udp))
            
            sorted_message = sorted([(k,v) for k,v in message.items()], key=lambda t:t[1], reverse=True)
            
            for i in sorted_message:
                f.write('json path: %s | %d\n' % (i[0], i[1]))
         

            
            
    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, get_sysinfo_count.get(device, 0), other_count.get(device, 0), udp_count.get(device, 0), tcp_count.get(device, 0), cmd_count.get(device, 0), rsp_count.get(device, 0))
        if (get_sysinfo_count.get(device, 0)+ other_count.get(device, 0)) == 0:
            continue
        return_list.append([device, get_sysinfo_count.get(device, 0), other_count.get(device, 0), udp_count.get(device, 0), tcp_count.get(device, 0), cmd_count.get(device, 0), rsp_count.get(device, 0)])

    header = ['device', 'get_sysinfo_count', 'other_count', 'udp_count', 'tcp_count', 'cmd_count', 'rsp_count']
    return (header, return_list)

        
        
    

def classicstun_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','classicstun')
    
    bind_request_count = {}
    share_request_count = {}
    other_count = {}
    # bind request: 1
    # share secret request: 2
    # classicstun.type == '257' # bind response
    # classicstun.type == '258' # share secret response
    mac_dic = read_mac_address()
    rev_mac_dict = {}
    for k,v in mac_dic.items():
        rev_mac_dict[v] = k
    for device in dict_dec:
        print('analyzing classic-stun packets...', device) # os.getpid()
        if device not in packets_dict:
            continue
        
        stun_dst = {}
        message = {}
        count = 0
        for packet in packets_dict[device]:
            # print(packet.classicstun)
            # exit(1)
            my_device_mac = mac_dic[device]
            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            stun_type = packet.classicstun.type
            # print(stun_type)
            if stun_type == '0x0001':
                bind_request_count[device] = bind_request_count.get(device, 0) + 1
            elif stun_type == '0x0002':
                share_request_count[device] = share_request_count.get(device, 0) + 1
            else:
                other_count[device] = other_count.get(device, 0) + 1
            if src_mac == my_device_mac:
                dst_dev = rev_mac_dict[dst_mac]
                stun_dst[dst_dev] = stun_dst.get(dst_dev, 0) + 1
                if packet.classicstun.length != '0x0000':
                    # print(packet.classicstun.length, packet.classicstun)
                    # message.append(packet.classicstun._all_fields)
                    message[stun_type] = message.get(stun_type, 0) + 1
            # count += 1
            # if count > 10000:
            #     break
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            sorted_stun_dst = sorted([(k,v) for k,v in stun_dst.items()], key=lambda t:t[1], reverse=True)
            
            for i in sorted_stun_dst:
                f.write('Dst %s: %d\n' % (i[0], i[1]))
            
            f.write('\n')
            # messages
            sorted_message = sorted([(k,v) for k,v in message.items()], key=lambda t:t[1], reverse=True)
            
            for i in sorted_message:
                f.write('Nonempty %s: %d\n' % (i[0], i[1]))

            
            
    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, bind_request_count.get(device, 0), share_request_count.get(device, 0), other_count.get(device, 0))
        if (bind_request_count.get(device, 0) + share_request_count.get(device, 0) + other_count.get(device, 0)) == 0:
            continue
        return_list.append([device, bind_request_count.get(device, 0), share_request_count.get(device, 0), other_count.get(device, 0)])

    header = ['device', 'bind_request_count', 'share_request_count', 'other_count']
    return (header, return_list)

def ssdp_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','ssdp')
    
    unicast_count = {}
    multicast_count = {}
    request_count = {}
    reply_count = {}
    mac_dict = read_mac_address()
    # ssdp&&!icmp
    for device in dict_dec:
        print('analyzing SSDP packets...', device)
        my_device_mac = mac_dict[device]
        if device not in packets_dict:
            continue
        
        target_device = {}
        request_info = {}
        request_method = {}
        response_code = {}
        response_location = ''
        response_server = ''
        count = 0 
        
        for packet in packets_dict[device]:
            # print(packet.ssdp._all_fields)
            if ("icmp" in str(packet.layers).lower()):
                continue
            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            request = 0
            if is_multicast(dst_mac):
                multicast_count[device] = multicast_count.get(device, 0) + 1 
                request_count[device] = request_count.get(device, 0) + 1 
                # print(packet.ssdp._all_fields)
                if packet.ssdp.http_request_method != 'M-SEARCH':
                    request_method[packet.ssdp.http_request_method] = request_method.get(packet.ssdp.http_request_method, 0) + 1
                    
                # print(packet.ssdp.http_request_method)
                # print(packet.ssdp.http_request_uri)
                # print(packet.ssdp.http_host)
                # print(packet.ssdp.http_request_full_uri)
                request_info[packet.ssdp.http_request_full_uri] = request_info.get(packet.ssdp.http_request_full_uri, 0) + 1
                
            else:
                unicast_count[device] = unicast_count.get(device, 0) + 1 
                # print(packet.ssdp)
                try:
                    tmp = packet.ssdp.http_request_method
                    # print(packet.ssdp.http_request_uri)
                    # print(packet.ssdp.http_host)
                    # print(packet.ssdp.http_request_full_uri)
                    request_count[device] = request_count.get(device, 0) + 1 
                    request = 1
                except:
                    # print(packet.ssdp.http_response_code)
                    # print(packet.ssdp.http_location)
                    # print(packet.ssdp.http_server)
                    reply_count[device] = reply_count.get(device, 0) + 1 
                if src_mac == my_device_mac:
                    if request == 1:
                        if packet.ssdp.http_request_method != 'M-SEARCH':
                            request_method[packet.ssdp.http_request_method] = request_method.get(packet.ssdp.http_request_method, 0) + 1
                        request_info[packet.ssdp.http_request_full_uri] = request_info.get(packet.ssdp.http_request_full_uri, 0) + 1
                    else:
                        response_code[packet.ssdp.http_response_code] = response_code.get(packet.ssdp.http_response_code, 0) + 1
                        if len(response_location) == 0:
                            response_location = packet.ssdp.http_location
                            response_server = packet.ssdp.http_server
                            
                        
                    
                    
            # print(packet.ssdp.http_host)
            # print(packet.http.request.method)
            # print(packet.http.request.url)
            # print(packet.http.request.host)
            # print(packet.http.request.full_url)
            # count += 1
            # if count > 30:
            #     exit(0)
                
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            # request method
            if len(request_method) != 0:
                sorted_request_method = sorted([(k,v) for k,v in request_method.items()], key=lambda t:t[1], reverse=True)
            
                for i in sorted_request_method:
                    f.write('Request method %s: %d\n' % (i[0], i[1]))
            
            # request info
            sorted_request_info = sorted([(k,v) for k,v in request_info.items()], key=lambda t:t[1], reverse=True)
            for i in sorted_request_info:
                f.write('Request full uri %s: %d\n' % (i[0], i[1]))
                
            # response:
            f.write('\n')
            # response code
            sorted_response_code = sorted([(k,v) for k,v in response_code.items()], key=lambda t:t[1], reverse=True)
            for i in sorted_response_code:
                f.write('Response code %s: %d\n' % (i[0], i[1]))
            if len(response_location) != 0:
                f.write('Response location: ')
                f.write('%s\n' % response_location)
            if len(response_server) != 0:
                f.write('Response server: %s\n' % response_server)
            
    
    return_list = []
    for device in dict_dec:
        # count += 1
        print(device, unicast_count.get(device, 0), multicast_count.get(device, 0), request_count.get(device, 0), reply_count.get(device, 0))
        if (unicast_count.get(device, 0) + multicast_count.get(device, 0) ) == 0:
            continue
        return_list.append([device, unicast_count.get(device, 0), multicast_count.get(device, 0), request_count.get(device, 0), reply_count.get(device, 0)])
        
    header = ['device', 'unicast_count', 'multicast_count', 'request_count', 'reply_count']
    return (header, return_list)

def icmp_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','icmp')

    to_router = {}
    to_dns_server = {}
    to_other_dev = {}
    other = {}
    unreachable = {}
    request_reply = {}

    mac_dict = read_mac_address()
    rev_mac_dict = {}
    for k,v in mac_dict.items():
        rev_mac_dict[v] = k
    # TODO
    for device in dict_dec:
        print('analyzing ICMP packets...', device)
        if device not in packets_dict:
            continue
        
        my_device_mac = mac_dict[device]
        unreachable_dev = {}
        ping_dev = {}
        other_icmp = {}

        for packet in packets_dict[device]:
            # print(packet)
            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            dst_ip = packet.ip.dst
            src_ip = packet.ip.src
                
            if dst_ip.startswith('155') or dst_ip.startswith('8.8'):
                # continue
                to_dns_server[device] = to_dns_server.get(device, 0) + 1 
                unreachable[device] = unreachable.get(device, 0) + 1
                continue
            if not dst_ip.startswith('192.168') or not src_ip.startswith('192.168'):
                continue
            # print(src_mac, dst_mac)
            if is_router(src_mac, dst_mac):
                to_router[device] = to_router.get(device, 0) + 1 
            

            if packet.icmp.type != '0' and packet.icmp.type != '8':
                if packet.icmp.type=='3':
                    unreachable[device] = unreachable.get(device, 0) + 1
                    if dst_mac == my_device_mac:
                        tmp_dev = rev_mac_dict[src_mac]
                        unreachable_dev[tmp_dev] = unreachable_dev.get(tmp_dev, 0) + 1
                else:
                    other_icmp[packet.icmp.type] = other_icmp.get(packet.icmp.type, 0) + 1
                    other[device] = other.get(device, 0) + 1
            else:
                request_reply[device] = request_reply.get(device, 0) + 1
                    
                if src_mac == my_device_mac: 
                    tmp_dev = rev_mac_dict[dst_mac]
                    ping_dev[tmp_dev] = ping_dev.get(tmp_dev, 0) + 1
                    if tmp_dev!='router':
                        to_other_dev[device] = to_other_dev.get(device, 0) + 1 
                    

        
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            sorted_unreachable_dev = sorted([(k,v) for k,v in unreachable_dev.items()], key=lambda t:t[1], reverse=True)
            
            # reply unreachable
            for i in sorted_unreachable_dev:
                f.write('unreachable %s: %d\n' % (i[0], i[1]))
            
            f.write('\n')
            # pinged device 
            sorted_ping_dev = sorted([(k,v) for k,v in ping_dev.items()], key=lambda t:t[1], reverse=True)
            for i in sorted_ping_dev:
                f.write('pinged %s: %d\n' % (i[0], i[1]))
                
            # other icmp type
            sorted_other_icmp = sorted([(k,v) for k,v in other_icmp.items()], key=lambda t:t[1], reverse=True)
            for i in sorted_other_icmp:
                f.write('other type %s: %d\n' % (i[0], i[1]))
            
            
    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, to_router.get(device, 0), to_dns_server.get(device, 0), to_other_dev.get(device, 0), other.get(device, 0), unreachable.get(device, 0), request_reply.get(device, 0))
        if (to_router.get(device, 0) + to_dns_server.get(device, 0) + to_other_dev.get(device, 0) + other.get(device, 0) +  unreachable.get(device, 0) + request_reply.get(device, 0) ) == 0:
            continue
        return_list.append([device, to_router.get(device, 0), to_dns_server.get(device, 0), to_other_dev.get(device, 0), other.get(device, 0), unreachable.get(device, 0), request_reply.get(device, 0)])
        # to_router_all += to_router.get(device, 0)
        # to_dns_server_all += to_dns_server.get(device, 0)
        # # if broadcast_count.get(device, 0) != 0:
        # #     broadcast_not_zero += 1
        # other_all += other.get(device, 0)
        # unreachable_all += unreachable.get(device, 0)
        # request_reply_all += request_reply.get(device, 0)
    # print('Overall %d devices' % count, to_router_all, to_dns_server_all, other_all, unreachable_all, request_reply_all)
    header = ['device', 'to_router', 'to_dns_server', 'to_other_dev', 'other', 'unreachable', 'request_reply']
    return (header, return_list)

def arp_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','arp')
    ip_dic = read_device_ip()
    # ip_dic['254'] = 0
    # ip_dic['255'] = 0
    # print(ip_list)
    
    unicast_count = {}
    broadcast_count = {}
    remote_ip_count = {}
    unassigned_ip_count = {}
    request_count = {}
    reply_count = {}
    mac_dict = read_mac_address()
    for device in dict_dec:
        print('analyzing ARP packets...', device)
        my_device_mac = mac_dict[device]
        if device not in packets_dict:
            # unicast_count[device] = 0
            # broadcast_count[device] = 0
            # unassigned_ip_count[device] = 0
            # request_count[device] = 0
            # reply_count[device] = 0
            continue
        
        target_device = {}
        for packet in packets_dict[device]:
            dst_mac = packet.eth.dst
            if is_broadcast(dst_mac):
                broadcast_count[device] = broadcast_count.get(device, 0) + 1 
            else:
                unicast_count[device] = unicast_count.get(device, 0) + 1 
                # print(packet.arp.dst_proto_ipv4)
                # target_ip = packet.arp.dst_proto_ipv4
                # target_ip = target_ip.split('.')[-1]
                # if target_ip not in ip_dic:
                #     unassigned_ip_count[device] = unassigned_ip_count.get(device, 0) + 1 
                    
            if packet.arp.opcode == '1':
                request_count[device] = request_count.get(device, 0) + 1
            elif packet.arp.opcode == '2':
                reply_count[device] = reply_count.get(device, 0) + 1
            else:
                print('Other arp: ', packet.arp)
            
            # print(packet.sniff_timestamp)
            cur_time = float(packet.sniff_timestamp)
            my_time = datetime.datetime.fromtimestamp(cur_time).strftime('%Y-%m-%d %H:%M:%S')
            # my_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cur_time))
            # print(my_time)
            if packet.arp.opcode == '1' and packet.arp.src_hw_mac == my_device_mac:
                target_ip = packet.arp.dst_proto_ipv4
                if packet.arp.src_proto_ipv4 == target_ip:
                    # arp announcement
                    continue
                if not target_ip.startswith('192.168.10.'):
                    target_device[target_ip] = target_device.get(target_ip, 0) + 1
                    remote_ip_count[device] = remote_ip_count.get(device, 0) + 1
                    continue
                target_ip = target_ip.split('.')[-1]
                if target_ip == '254':
                    target_device['Router'] = target_device.get('Router', 0) + 1
                    continue
                elif target_ip not in ip_dic:
                    unassigned_ip_count[device] = unassigned_ip_count.get(device, 0) + 1 
                    target_device[target_ip] = target_device.get(target_ip, 0) + 1
                    continue

                if len(ip_dic[target_ip]) == 1:
                    tmp_dev = [i for i in ip_dic[target_ip]][0]
                    target_device[tmp_dev] = target_device.get(tmp_dev, 0) + 1
                else:
                    tmp_time = '0'
                    tmp_dev = 0
                    for dev, time in ip_dic[target_ip].items():
                        if (tmp_time < time) and (time < my_time):
                            tmp_time = time 
                            tmp_dev = dev
                    target_device[tmp_dev] = target_device.get(tmp_dev, 0) + 1
        
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        print(target_device)
        with open(out_file, 'w') as f:
            sorted_target_device = sorted([(k,v) for k,v in target_device.items()], key=lambda t:t[1], reverse=True)
            for d in sorted_target_device:
                f.write('%s: %d\n' % (d[0], d[1]))
        

    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, broadcast_count.get(device, 0), unicast_count.get(device, 0), remote_ip_count.get(device, 0), unassigned_ip_count.get(device, 0), request_count.get(device, 0), reply_count.get(device, 0))
        if (broadcast_count.get(device, 0) + unicast_count.get(device, 0)) == 0:
            continue
        return_list.append([device, broadcast_count.get(device, 0), unicast_count.get(device, 0),  remote_ip_count.get(device, 0), unassigned_ip_count.get(device, 0), request_count.get(device, 0), reply_count.get(device, 0)])

    

    header = ['device', 'broadcast_count', 'unicast_count', 'remote_ip_count', 'unassigned_local_ip_count', 'request_count', 'reply_count']
    return (header, return_list)

def dhcp_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','dhcp')
    to_router = {}
    broadcast_count = {}
    other = {}
    not_request_ack = {}
    for device in dict_dec:
        print('analyzing DHCP packets...', device) # os.getpid()
        if device not in packets_dict:
            to_router[device] = 0 
            broadcast_count[device] = 0 
            other[device] = 0 
            not_request_ack[device] = 0
            continue
        request_info = set()
        vendor_class_id = ''
        dhcp_type = {}
        for packet in packets_dict[device]:
            # print(packet)

            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            # print(src_mac, dst_mac)
            if is_router(src_mac, dst_mac):
                to_router[device] = to_router.get(device, 0) + 1 
            elif is_broadcast(dst_mac):
                broadcast_count[device] = broadcast_count.get(device, 0) + 1 
            else:
                other[device] = other.get(device, 0) + 1 

            if packet.dhcp.option_dhcp != '3' and packet.dhcp.option_dhcp != '5':
                not_request_ack[device] = not_request_ack.get(device, 0) + 1
            dhcp_type[packet.dhcp.option_dhcp] = dhcp_type.get(packet.dhcp.option_dhcp, 0) + 1
            
            if len(request_info) == 0 and packet.dhcp.type == '1':
                # print(packet.dhcp._all_fields, packet.dhcp.option_dhcp)
                # print('Request info:',packet.dhcp, packet.dhcp.option_request_list_item) # packet.dhcp._all_fields)
                # print(packet.dhcp) # .get_field_value('option_request_list_item')
                # exit(1)
                for line in packet.dhcp._get_all_field_lines():
                    if line.strip().startswith('Parameter'):
                        # print(line)
                        request_info.add(line.strip().split(':')[1])
            elif packet.dhcp.option_dhcp == '1':
                for line in packet.dhcp._get_all_field_lines():
                    if line.strip().startswith('Parameter'):
                        # print(line)
                        request_info.add(line.strip().split(':')[1])
                
            if len(vendor_class_id) == 0:
                try:
                    vendor_class_id = packet.dhcp.option_vendor_class_id
                except:
                    continue
        # write outputs for each device
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        with open(out_file, 'w') as f:
            f.write('Parameter Request List: \n')
            for p in request_info:
                f.write(p)
                f.write('\n')
            if len(vendor_class_id) != 0:
                f.write('Vendor class identifier: ')
                f.write('%s\n' % vendor_class_id)
            if len(dhcp_type) != 0:
                f.write('DHCP type: \n')
                for k in dhcp_type:
                    f.write('type %s: %d\n' % (k, dhcp_type[k]) )
            
    # to_router_all = 0
    # broadcast_count_all = 0
    # other_all = 0
    # not_request_ack_all = 0
    # broadcast_not_zero = 0
    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, to_router.get(device, 0), broadcast_count.get(device, 0), other.get(device, 0), not_request_ack.get(device, 0))
        return_list.append([device, to_router.get(device, 0), broadcast_count.get(device, 0), other.get(device, 0), not_request_ack.get(device, 0)])

    #     to_router_all += to_router.get(device, 0)
    #     broadcast_count_all += broadcast_count.get(device, 0)
    #     if broadcast_count.get(device, 0) != 0:
    #         broadcast_not_zero += 1
    #     other_all += other.get(device, 0)
    #     not_request_ack_all += not_request_ack.get(device, 0)
    # print('Overall %d devices' % count, to_router_all, broadcast_count_all, other_all, not_request_ack_all, '%d devices use broadcast' % broadcast_not_zero)
    
    header = ['device', 'to_router', 'broadcast_count', 'other_count', 'not_request_ack']
    return (header, return_list)


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
        case 'http': # TODO
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