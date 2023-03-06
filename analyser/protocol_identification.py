from analyser.utils import * 
import analyser.flow_extraction_new as flow_extraction_new
from . import plotting

def multiprocessing_protocol_identification(out_dir, dict_dec, all_packets_captures):
    """The mutliprocessing wrapper for per protocol identification 

    Args:
        out_dir (string): output dir 
        dict_dec (dict): dictionary of devices.
        all_packets_captures (dict): dictionary of packets for each device 
    """
    try:
        cpu_count = int(multiprocessing.cpu_count())
        num_proc = cpu_count-2
    except:
        num_proc = 30
    # num_proc = 1
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
        print('Process %d:' % i, new_packets_captures.keys())
        p = Process(target=protocol_identification_wrapper, args=(device_list, new_packets_captures, i ,return_dict, out_dir))
        procs.append(p)
        p.start()

    for p in procs:
        p.join()
    
    print('Protocol_identification...Outputing...')
    # * outputs: 
    
    protocols_out_dir = os.path.join(out_dir, 'protocol_statistics_pyshark')
    if not os.path.exists(protocols_out_dir):
        os.system('mkdir -pv %s' % protocols_out_dir) 
    
    
    
    protocol_dict = {}
    destination_distribution_dict = {} # {device: set(dst)}
    protocol_distribution_per_addressing_method = {} # {device: [{unicast protocol: count}, {multicast protocol: count}, {broadcast protocol: count}]}
    eth_unicast_dict = {} # {device: {protocol:count}}
    for k, v in return_dict.items():
        # print(k,v)
        protocol_dict = protocol_dict | v[0]
        # addressing_method_list = addressing_method_list | v[1]
        destination_distribution_dict = destination_distribution_dict | v[1]
        protocol_distribution_per_addressing_method = protocol_distribution_per_addressing_method | v[2]
        eth_unicast_dict = eth_unicast_dict | v[3]
        
    
    return_dict = {'protocol_dict':protocol_dict,
                   'destination_distribution_dict':destination_distribution_dict,
                   'protocol_distribution_per_addressing_method':protocol_distribution_per_addressing_method,
                   'eth_unicast_dict':eth_unicast_dict}
    return_dict_output = protocols_out_dir + '/_return_dict.model' 
    pickle.dump(return_dict, open(return_dict_output, 'wb'))
    print('protocol_distribution_per_addressing_method: ', protocol_distribution_per_addressing_method)
    
    f_unicast = open(os.path.join(protocols_out_dir, '_unicast.txt'), 'w')
    f_multicast = open(os.path.join(protocols_out_dir, '_multicast.txt'), 'w')
    f_broadcast = open(os.path.join(protocols_out_dir, '_broadcast.txt'), 'w')
    
    addressing_method_list = {} # {device: [unicast count, multicast count, broadcast count]} 
    unicast_tmp = {} # {protocol: {device: count}}
    multicast_tmp = {}
    broadcast_tmp = {}
    
    
    for device in protocol_distribution_per_addressing_method:
        addressing_method_list[device] = [0,0,0]
        f_unicast.write(('%s\n') % device)
        for cur_protocol, count in protocol_distribution_per_addressing_method[device][0].items():
            if cur_protocol not in unicast_tmp:
                unicast_tmp[cur_protocol] = {device: 0}
            elif device not in unicast_tmp[cur_protocol]:
                unicast_tmp[cur_protocol][device] = 0
            unicast_tmp[cur_protocol][device] += count
            f_unicast.write('  %s, %d\n' % (cur_protocol, count))
            addressing_method_list[device][0] += count
        f_unicast.write('\n')
        
        f_multicast.write(('%s\n') % device)
        for cur_protocol, count in protocol_distribution_per_addressing_method[device][1].items():
            if cur_protocol not in multicast_tmp:
                multicast_tmp[cur_protocol] = {device: 0}
            elif device not in multicast_tmp[cur_protocol]:
                multicast_tmp[cur_protocol][device] = 0
            multicast_tmp[cur_protocol][device] += count
            f_multicast.write('  %s, %d\n' % (cur_protocol, count))
            addressing_method_list[device][1] += count
        f_multicast.write('\n')
        
        f_broadcast.write(('%s\n') % device)
        for cur_protocol, count in protocol_distribution_per_addressing_method[device][2].items():
            if cur_protocol not in broadcast_tmp:
                broadcast_tmp[cur_protocol] = {device: 0}
            elif device not in broadcast_tmp[cur_protocol]:
                broadcast_tmp[cur_protocol][device] = 0
            broadcast_tmp[cur_protocol][device] += count
            f_broadcast.write('  %s, %d\n' % (cur_protocol, count))
            addressing_method_list[device][2] += count
        f_broadcast.write('\n')
        
    f_unicast.close()
    f_multicast.close()
    f_broadcast.close()
    # # unicast:
    unicast_tmp_distribution = {x: len(unicast_tmp[x]) for x in unicast_tmp}
    plotting.plotting_bar(unicast_tmp_distribution, os.path.join(out_dir, 'vis', 'unicast_device_per_protocol') , '# of devices per protocol (unicast only)')
    # # multicast
    multicast_tmp_distribution = {x: len(multicast_tmp[x]) for x in multicast_tmp}
    plotting.plotting_bar(multicast_tmp_distribution, os.path.join(out_dir, 'vis', 'multicast_device_per_protocol') , '# of devices per protocol (multicast only)')
    # # broadcast
    broadcast_tmp_distribution = {x: len(broadcast_tmp[x]) for x in broadcast_tmp}
    plotting.plotting_bar(broadcast_tmp_distribution, os.path.join(out_dir, 'vis', 'broadcast_device_per_protocol') , '# of devices per protocol (broadcast only)')
    
    # # eth unicast
    eth_unicast_device_per_protocol = {}
    for dev in eth_unicast_dict:
        for prot in eth_unicast_dict[dev]:
            if prot not in eth_unicast_device_per_protocol:
                eth_unicast_device_per_protocol[prot] = {}
            eth_unicast_device_per_protocol[prot][dev] = eth_unicast_dict[dev][prot]
    eth_unicast_device_per_protocol_distribution = {x: len(eth_unicast_device_per_protocol[x]) for x in eth_unicast_device_per_protocol}
    plotting.plotting_bar(eth_unicast_device_per_protocol_distribution, os.path.join(out_dir, 'vis', 'eth_unicast_device_per_protocol') , '# of devices per protocol (eth unicast only)')
    
    # num of unicast packets per device
    unicast_distribution_dict = {x:addressing_method_list[x][0] for x in addressing_method_list}
    plotting.plotting_bar(unicast_distribution_dict, os.path.join(out_dir, 'vis', 'unicast_distribution_dict') , '# of unicast packet per device')
    
    # num of multicast packets per device
    multicast_distribution_dict = {x:addressing_method_list[x][1] for x in addressing_method_list}
    plotting.plotting_bar(multicast_distribution_dict, os.path.join(out_dir, 'vis', 'multicast_distribution_dict') , '# of multicast packet per device')
    
    # num of broadcast packets per device
    broadcast_distribution_dict = {x:addressing_method_list[x][2] for x in addressing_method_list}
    plotting.plotting_bar(broadcast_distribution_dict, os.path.join(out_dir, 'vis', 'broadcast_distribution_dict') , '# of broadcast packet per device')  
    
    # num of eth unicast packets per device
    eth_unicast_dict_packet = {}
    for dev in eth_unicast_dict:
        eth_unicast_dict_packet[dev] = 0
        for prot in eth_unicast_dict[dev]:
            eth_unicast_dict_packet[dev] += eth_unicast_dict[dev][prot]
    eth_unicast_dict_packet_distribution = {x:eth_unicast_dict_packet[x] for x in eth_unicast_dict_packet}
    plotting.plotting_bar(eth_unicast_dict_packet_distribution, os.path.join(out_dir, 'vis', 'eth_unicast_dict_packet_distribution') , '# of eht unicast packet per device')  
    with open(os.path.join(protocols_out_dir, '_eth_unicast.txt'), 'w') as f:
        # f.write('Average dst device: %.2f\n' % average_dst)
        # f.write('\n')
        for dev in eth_unicast_dict:
            f.write(('%s\n') % dev)
            for prot in eth_unicast_dict[dev]:
                f.write(('  %s, %d\n') % ( prot, eth_unicast_dict[dev][prot]))
            f.write(('\n'))

    # * count protocols
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

    
    
    # * dst device contacted (no router, unicast only)
    with open(os.path.join(protocols_out_dir, '_dst_device.txt'), 'w') as f:
        for x in destination_distribution_dict:
            f.write('%s : %s\n' % (x, ', '.join(list(destination_distribution_dict[x]))))
    average_dst = 0
    
    for x in destination_distribution_dict:
        destination_distribution_dict[x] = len(destination_distribution_dict[x])
        average_dst += destination_distribution_dict[x]
    # * average dst device contacted (no router, unicast only)
    average_dst = average_dst/len(destination_distribution_dict)
    
    with open(os.path.join(protocols_out_dir, '_dst.txt'), 'w') as f:
        f.write('Average dst device: %.2f\n' % average_dst)
        f.write('\n')
        for x in destination_distribution_dict:
            f.write('%s : %d\n' % (x, destination_distribution_dict[x]))
    
    # destination_distribution_dict
    plotting.plotting_bar(destination_distribution_dict, os.path.join(out_dir, 'vis', 'destination') , '# of contacted destination per device')
    # num of packets per addressing method per device. addressing_method_list: {device: {[uni num, multi num, broad num]}}
    plotting.plotting_multicolumn_bar(addressing_method_list, os.path.join(out_dir, 'vis', 'addressing_method_log'), '# of packet per addressing method per device')
    
    # TODO device contact except router

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
            
    
    
    # device per protocol log. Need manual correction
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
    protocol_dict = {} # packet count for each protocol by layer per device 
                       # {device: {layer:{protocol:packet count}}}
    # protocol_dict_inbound = {}  # inbound packet count 
    # protocol_dict_outbound = {}  # outbound packet count 
    # addressing_method_list = {} # packet count for each kind of addressing method per device  
    destination_distribution_dict = {} # how many destination devices each device contact
    # reached_device_distribution_dict = {} # how many devices talk with this device 
    protocol_distribution_per_addressing_method = {} # {device: [{protocol:count}, {protocol:count}, {protocol:count}]} # 0: unicast, 1: multicast, 2: broadcast
    eth_unicast_dict = {}
    
    # * for each device 
    for device in dict_dec:
        tmp_protocols = {'2':{}, '3':{}, '4':{}, '5':{}}
        # tmp_addressing_method_list = [0,0,0]    # 0: unicast, 1: multicast, 2: broadcast
        tmp_protocol_distribution_per_addressing_method = [{},{},{}]    # 0: unicast, 1: multicast, 2: broadcast
        # for f in dict_dec[device]:

        # cur_packets_set = pickle.load(open(os.path.join(out_dir, 'pcap', device, 'all.capture'), 'rb'))
        if device not in all_packets_captures:
            print('Device not in the captures: %s\n' % device)
            continue
        cur_packets_set = all_packets_captures[device]
        tmp_count = 0
        periodic_detection_packets = [] ## packet.frame_info.time_delta
        
        my_device_mac =  mac_dic[device]
        destination_set = set() # different destination device each device contact
        packet_count = {} # key: dst device, value: dict {protocol, number of packets}
        
        tmp_eth_unicast = {}
        
        
        tcp_output = {}
        udp_output = {}
        
        t1 = time.time()
        if not isinstance(cur_packets_set, list): # if only loaded one pcap file
            cur_packets_set = [cur_packets_set]
        # * for each packet set: one set for each pcap file
        for cur_packets in cur_packets_set:
            for packet in cur_packets:
                tmp_count += 1
                # if tmp_count%10000 == 0:
                    # print(tmp_count, time.time()-t1)
                is_UDP = False
                cur_layers = []
                sport = '0'
                dport = '0'
                # print(packet.eth)
                # print(packet.layers)
                try:
                    src_mac = packet.eth.src
                    dst_mac = packet.eth.dst
                except:
                    continue
                
                packet_length = packet.length
                # * get the protocol name of each layers
                for i in packet.layers:
                    cur_layers.append(i.layer_name)
                
                
                # * unicast multicast broadcast:
                tmp_addressing_flag = addressing_method(dst_mac)
                # tmp_addressing_method_list[tmp_addressing_flag] += 1
                
                # if not is_router(src_mac, dst_mac):
                #     # why? 
                #     tmp_addressing_flag = addressing_method(dst_mac)

                    
                # * different destination (other IoT devices) count, destination_distribution
                unicast_not_router = (tmp_addressing_flag == 0 and not is_router(src_mac, dst_mac))
                if unicast_not_router:    # unicast and not router
                    if dst_mac == my_device_mac and src_mac in inv_mac_dic:
                        dst_dev = inv_mac_dic[src_mac]
                        destination_set.add(dst_dev)
                    elif src_mac == my_device_mac and dst_mac in inv_mac_dic:
                        dst_dev = inv_mac_dic[dst_mac]
                        destination_set.add(dst_dev)
                
                # * layer 2 eth: all packet count 
                # print(tmp_protocols)
                tmp_protocols['2'][cur_layers[0]] = tmp_protocols['2'].get(cur_layers[0], 0) + 1
                
                # * layer 3: IP or Non IP, v4 and v6
                tmp_protocols['3'][cur_layers[1]] = tmp_protocols['3'].get(cur_layers[1], 0) + 1
                highest_protocol = cur_layers[1]
                if cur_layers[1]!='ip' and cur_layers[1]!='ipv6' and tmp_addressing_flag==0:
                    # layer2 eth unicast
                    tmp_eth_unicast[cur_layers[1]] = tmp_eth_unicast.get(cur_layers[1], 0) + 1
                
                # * layer 4: TCP UDP (or other layer 3 protocols built upon IP)
                if len(cur_layers) > 2:
                    tmp_protocols['4'][cur_layers[2]] = tmp_protocols['4'].get(cur_layers[2], 0) + 1
                    if cur_layers[2] == 'udp':
                        is_UDP = True
                        sport = packet.udp.srcport
                        dport = packet.udp.dstport
                        if unicast_not_router:
                            if dst_dev not in udp_output:
                                udp_output[dst_dev] = 0
                            udp_output[dst_dev] += int(packet_length)
                    elif cur_layers[2] == 'tcp':
                        sport = packet.tcp.srcport
                        dport = packet.tcp.dstport
                        if unicast_not_router:
                            if dst_dev not in tcp_output:
                                tcp_output[dst_dev] = 0
                            tcp_output[dst_dev] += int(packet_length)
                    highest_protocol = cur_layers[2]
                    
                # * layer 5
                if len(cur_layers) > 3 and cur_layers[2] != 'icmp' and cur_layers[3].lower() != 'data' and cur_layers[3] != 'ajp13':
                    tmp_layer_name = cur_layers[3]
                    if tmp_layer_name == 'tcp.segments' and len(cur_layers) > 4:
                        tmp_layer_name = cur_layers[4]
                        
                    if is_UDP and tmp_layer_name not in ['dns','mdns', 'dhcp', 'ssdp', 'classicstun', 'tplink-smarthome'] and len(packet.udp.payload) > 350:
                        # print(tmp_layer_name)
                        if check_upnp(packet.udp.payload): 
                            # is UPnP/SSDP
                            tmp_layer_name = 'ssdp'
                    if tmp_layer_name.lower() != 'data':
                        tmp_protocols['5'][tmp_layer_name] = tmp_protocols['5'].get(tmp_layer_name, 0) + 1
                        highest_protocol = tmp_layer_name
                # print(tmp_protocols)
                
                # if is_UDP and cur_layers.index('udp') != len(cur_layers)-1 and \
                    # cur_layers[cur_layers.index('udp')+1] not in ['dns','mdns','data', 'dhcp', 'ssdp', 'classicstun', 'tplink-smarthome']:
                
                # * protocol per addressing method
                
                if highest_protocol not in tmp_protocol_distribution_per_addressing_method[tmp_addressing_flag]:
                    tmp_protocol_distribution_per_addressing_method[tmp_addressing_flag][highest_protocol] = 0
                tmp_protocol_distribution_per_addressing_method[tmp_addressing_flag][highest_protocol] += 1
                
                
                
                # * periodic detection preprocessing
                inbound = 0
                if dst_mac == my_device_mac:
                    # if inbound traffic, swap src and dst to build only one 5-tuple for both inbound and outbound traffic
                    tmp_mac = src_mac
                    src_mac = dst_mac
                    dst_mac = tmp_mac
                    tmp_port = sport
                    sport = dport
                    dport = tmp_port
                    inbound = 1
                
                if dst_mac in inv_mac_dic:
                    dst_dev = inv_mac_dic[dst_mac]
                else:
                    dst_dev = dst_mac
                periodic_detection_packets.append([packet.sniff_timestamp, packet.frame_info.time_delta, highest_protocol, dst_dev, sport, dport, packet_length, inbound])
                
                
                # * packet count per protocol per destination device
                if dst_dev not in packet_count:
                    packet_count[dst_dev] = {}
                if highest_protocol not in packet_count[dst_dev]:
                    packet_count[dst_dev][highest_protocol] = 0
                packet_count[dst_dev][highest_protocol] += 1
                
        # * Flow extraction for periodic detection  
        flows = flow_extraction_new.extract_single(periodic_detection_packets)
        bursts = flow_extraction_new.burst_split(flows)
        
        header = ['time_epoch', 'time_delta', 'protocol', 'dst', 'sport', 'dport'] 
        flow_extraction_new.flows_output(bursts, out_dir, device)
        
        # * plot device-level charts 
        # TODO Distribution of protocol by number of packets
        # TODO Distribution of protocol by total size
        
        # * TCP UDP output for vis
        output_file = output_file_generator(out_dir, 'tcp_output', device)
        
        with open(output_file, 'w') as ff:
            for k,v in sorted(tcp_output.items()):
                ff.write(('%s %d\n') % (k, v))
        
        output_file = output_file_generator(out_dir, 'udp_output', device)

        with open(output_file, 'w') as ff:
            for k,v in sorted(udp_output.items()):
                ff.write(('%s %d\n') % (k, v))
        
        # * write device-level output logs
        packet_count_dir = os.path.join(out_dir, 'new_packet_count')
        output_file = os.path.join(packet_count_dir ,device + '.txt') # Output file
        if not os.path.exists(packet_count_dir):
            os.system('mkdir -pv %s' % packet_count_dir)
        outputs = packet_count
        with open(output_file, 'w') as ff:
            for k,v in sorted(outputs.items()):
                ff.write(('%s\n') % k)
                # reached_device_distribution_dict[k] = reached_device_distribution_dict.get(k, 0) + 1
                # print(k)
                for k2 in v:
                    ff.write(('  %s, %d\n') % ( k2, v[k2]))
                    # print('  ', k2, v[k2])
                ff.write(('\n'))
        
        
        # * return results
        print('Processing %s...packet count: %d, time: %.2f' % (device, tmp_count, time.time()-t1))
        protocol_dict[device] = tmp_protocols
        # addressing_method_list[device] = tmp_addressing_method_list
        destination_distribution_dict[device] = destination_set
        protocol_distribution_per_addressing_method[device] = tmp_protocol_distribution_per_addressing_method
        eth_unicast_dict[device] = tmp_eth_unicast
        # addressing_method_list
    return [protocol_dict, destination_distribution_dict, protocol_distribution_per_addressing_method, eth_unicast_dict]
        
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

