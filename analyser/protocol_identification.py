from analyser.utils import * 
import analyser.flow_extraction_new as flow_extraction_new

def multiprocessing_protocol_identification(out_dir, dict_dec, all_packets_captures):
    """The mutliprocessing wrapper for per protocol identification 

    Args:
        out_dir (string): output dir 
        dict_dec (dict): dictionary of devices.
        all_packets_captures (dict): dictionary of packets for each device 
    """
    num_proc = 20
    in_dev = [ [] for _ in range(num_proc) ]
    index = 0 
    for device in dict_dec:
        in_dev[index % num_proc].append(device)
        index += 1

    print('Mutliprocessing... ', len(in_dev))
    procs = []
    manager = Manager()
    return_dict = manager.dict()
    for i in range(len(in_dev)):
        device_list = in_dev[i]
        if len(device_list)==0:
            continue
        new_packets_captures = {}
        for device in device_list:
            if device not in all_packets_captures:
                continue
            new_packets_captures[device] = all_packets_captures[device]

        p = Process(target=protocol_identification_wrapper, args=(device_list, new_packets_captures, i ,return_dict, out_dir))
        procs.append(p)
        p.start()

    for p in procs:
        p.join()
    
    # return 0

    protocols_out_dir = os.path.join(out_dir, 'protocol_statistics_pyshark')
    if not os.path.exists(protocols_out_dir):
        os.system('mkdir -pv %s' % protocols_out_dir) 
        
    
    protocol_dict = {}
    addressing_method_list = {}
    for k, v in return_dict.items():
        # print(k,v)
        protocol_dict = protocol_dict | v[0]
        addressing_method_list = addressing_method_list | v[1]

    count_all = {}
    count_ip = {}
    count_v6 = {}
    count_tcp = {}
    count_udp = {}
    count_tls = {}
    protocol_set = set()
    protocol_set.add('eth')
    for dev in protocol_dict:
        count_all[dev] = protocol_dict[dev]['2'].get('eth', 0)
        count_ip[dev] = 0
        count_v6[dev] = 0
        count_tcp[dev] = 0
        count_udp[dev] = 0
        count_tls[dev] = 0
        layer3_protocol = protocol_dict[dev]['3']
        layer4_protocol = protocol_dict[dev]['4']
        layer5_protocol = protocol_dict[dev]['5']
        # count IP and Non IP
        for cur_protocol in layer3_protocol:
            protocol_set.add(cur_protocol)
            if cur_protocol == 'ip' or cur_protocol == 'ipv6':
                count_ip[dev] += layer3_protocol[cur_protocol]
                # IPv4 and IPv6
                if cur_protocol == 'ipv6':
                    count_v6[dev] += layer3_protocol[cur_protocol]

        # UDP and TCP
        for cur_protocol in layer4_protocol:
            protocol_set.add(cur_protocol)
            if cur_protocol == 'tcp':
                count_tcp[dev] += layer4_protocol[cur_protocol]
            elif cur_protocol == 'udp':
                count_udp[dev] += layer4_protocol[cur_protocol]

        # tls
        for cur_protocol in layer5_protocol:
            protocol_set.add(cur_protocol)
            if cur_protocol == 'tls' or cur_protocol == 'ssl':
                count_tls[dev] += layer5_protocol[cur_protocol]

    protocol_device_count = {}
    for i in protocol_set:
        protocol_device_count[i] = set()
        
    for dev in protocol_dict:
        with open(os.path.join(protocols_out_dir, '%s.txt' % dev), 'w') as f:
            f.write('Overall: %d\n' % count_all[dev])
            f.write('IP: %d\n' % count_ip[dev])
            f.write('IPv6: %d\n' % count_v6[dev])
            f.write('TCP: %d\n' % count_tcp[dev])
            f.write('UDP: %d\n' % count_udp[dev])
            f.write('TLS: %d\n' % count_tls[dev])
            
            for k in protocol_dict[dev]:
                f.write('Layer %s: %s\n' % (k, json.dumps(protocol_dict[dev][k]))) 
                for j in protocol_dict[dev][k]:
                    protocol_device_count[j].add(dev)
            f.write('\n')
            f.write('Unicast: %d\n' % addressing_method_list[dev][0])
            f.write('Multicast: %d\n' % addressing_method_list[dev][1])
            f.write('Broadcast: %d\n' % addressing_method_list[dev][2])
    
    with open(os.path.join(protocols_out_dir, '_overall.txt'), 'w') as f:

            
        sorted_protocol_device_count = sorted([(k,len(v)) for k,v in protocol_device_count.items()], key=lambda t:t[1], reverse=True)
        for i in sorted_protocol_device_count:
            # if i[0] == 'eth':
            #     continue
            f.write('%s: %d | %s\n\n' % (i[0], i[1], ', '.join(list(protocol_device_count[i[0]]))))
            

def protocol_identification_wrapper(dict_dec, all_packets_captures, procnum, return_dict, out_dir):
    return_dict[procnum] = protocol_identification(dict_dec, all_packets_captures, out_dir)

def protocol_identification(dict_dec, all_packets_captures, out_dir):
    """_summary_

    Args:
        out_dir (_type_): output dir
        dict_dec (_type_): dict of devices with input files 
        all_packets_captures (_type_): pyshark capture objects 
    """
    mac_dic = read_mac_address()
    inv_mac_dic = {v: k for k, v in mac_dic.items()}
    protocol_dict = {}
    addressing_method_list = {}
    for device in dict_dec:
        tmp_protocols = {'2':{}, '3':{}, '4':{}, '5':{}}
        tmp_addressing_method_list = [0,0,0]
        # for f in dict_dec[device]:

        cur_packets_set = all_packets_captures[device]
        tmp_count = 0
        periodic_detection_packets = []## packet.frame_info.time_delta
        my_device_mac =  mac_dic[device]
        
        t1 = time.time()
        for cur_packets in cur_packets_set:
            for packet in cur_packets:
                tmp_count += 1
                if tmp_count%10000 == 0:
                    print(tmp_count, time.time()-t1)
                is_UDP = False
                cur_layers = []
                sport = '0'
                dport = '0'
                for i in packet.layers:
                    cur_layers.append(i.layer_name)

                # unicast multicast broadcast:
                tmp_addressing_method_list[addressing_method(packet.eth.dst)] += 1
                
                # layer 2 eth: all packet count 
                # print(tmp_protocols)
                tmp_protocols['2'][cur_layers[0]] = tmp_protocols['2'].get(cur_layers[0], 0) + 1
                
                # layer 3: IP or Non IP, v4 and v6
                tmp_protocols['3'][cur_layers[1]] = tmp_protocols['3'].get(cur_layers[1], 0) + 1
                highest_protocol = cur_layers[1]
                # layer 4: TCP UDP (or other layer 3 protocols built upon IP)
                if len(cur_layers) > 2:
                    tmp_protocols['4'][cur_layers[2]] = tmp_protocols['4'].get(cur_layers[2], 0) + 1
                    if cur_layers[2] == 'udp':
                        is_UDP = True
                        sport = packet.udp.srcport
                        dport = packet.udp.dstport
                    elif cur_layers[2] == 'tcp':
                        sport = packet.tcp.srcport
                        dport = packet.tcp.dstport
                    highest_protocol = cur_layers[2]
                    
                # layer 5
                if len(cur_layers) > 3 and cur_layers[2] != 'icmp' and cur_layers[3] != 'data' and cur_layers[3] != 'ajp13':
                    tmp_layer_name = cur_layers[3]
                    if tmp_layer_name == 'tcp.segments' and len(cur_layers) > 4:
                        tmp_layer_name = cur_layers[4]
                        
                    if is_UDP and tmp_layer_name not in ['dns','mdns', 'dhcp', 'ssdp', 'classicstun', 'tplink-smarthome'] and len(packet.udp.payload) > 350:
                        # print(tmp_layer_name)
                        if check_upnp(packet.udp.payload): 
                            # is UPnP/SSDP
                            tmp_layer_name = 'ssdp'
                    
                    tmp_protocols['5'][tmp_layer_name] = tmp_protocols['5'].get(tmp_layer_name, 0) + 1
                    highest_protocol = tmp_layer_name
                # print(tmp_protocols)
                
                # if is_UDP and cur_layers.index('udp') != len(cur_layers)-1 and \
                    # cur_layers[cur_layers.index('udp')+1] not in ['dns','mdns','data', 'dhcp', 'ssdp', 'classicstun', 'tplink-smarthome']:
                src_mac = packet.eth.src
                dst_mac = packet.eth.dst
                if dst_mac == my_device_mac:
                    tmp_mac = src_mac
                    src_mac = dst_mac
                    dst_mac = tmp_mac
                    tmp_port = sport
                    sport = dport
                    dport = tmp_port
                
                if dst_mac in inv_mac_dic:
                    dst_dev = inv_mac_dic[dst_mac]
                else:
                    dst_dev = dst_mac
                periodic_detection_packets.append([packet.sniff_timestamp, packet.frame_info.time_delta, highest_protocol, dst_dev, sport, dport])
                
        
        flows = flow_extraction_new.extract_single(periodic_detection_packets)
        bursts = flow_extraction_new.burst_split(flows)
        print(tmp_count, time.time()-t1)
        
        
        
        header = ['time_epoch', 'time_delta', 'protocol', 'dst', 'sport', 'dport'] 
        flow_extraction_new.flows_output(bursts, out_dir, device)
        
        protocol_dict[device] = tmp_protocols
        addressing_method_list[device] = tmp_addressing_method_list
    return [protocol_dict, addressing_method_list]
        
def check_upnp(udp_payload):
    udp_payload = ''.join(udp_payload.split(':'))
    # print(udp_payload)
    try:
        decoded_payload = bytes.fromhex(udp_payload).decode('utf-8')
        # print(decoded_payload)
    except:
        return False
    if 'ssdp' in decoded_payload.lower() or 'upnp' in decoded_payload.lower():
        return True
    return False

