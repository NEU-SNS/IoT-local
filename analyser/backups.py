
# ! backup only, most functions here are deprecated

def extract_pcap(pcap_file:str) -> list[list[str]]:
    """extract features from a pcap file
    
    Args:
        pcap_file (_type_): PCAP file 

    Returns:
        list[list[str]]: list of packets
    """
    global mac_dic
    dev_name = pcap_file.split('/')[-2]

    feature_header = ['number', 'time_epoch', 'time_delta', 'len (size)', 'src mac', 'dst mac', 'Protocol', 'layer 4 protocol code (optional)', 
                    'TCP/UDP stream (optional)', 'src ip (optional)', 'dst ip (optional)', 'src port (optional)', 'dst port (optional)']

    command = ["tshark", "-r", pcap_file, 
                "-Y", 'not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission',
                "-Tfields",
                "-e", "frame.number",
                "-e", "frame.time_epoch",
                "-e", "frame.time_delta",
                "-e", "frame.len",
                "-e", "eth.src",
                "-e", "eth.dst",
                "-e", "_ws.col.Protocol",
                "-e", "ip.proto",   # layer 4 protocol id
                "-e", "ipv6.nxt",   # layer 4 protocol id
                "-e", "tcp.stream",
                "-e", "udp.stream",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.srcport",
                "-e", "udp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.dstport"
                ] # "-e", "_ws.expert"  tcp.analysis.flags
                # "-e", "ip.proto" # it returns transport layer protocol code. 
    result = []
    # Call Tshark on packets
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output. Give warning message if any
    out, err = process.communicate()
    if err:
        print("Error reading file: '{}'".format(err.decode('utf-8')))


    # Parsing packets
    my_device_mac =  mac_dic[dev_name]
    # print('Processing')
    
    for packet in filter(None, out.decode('utf-8').split('\n')):
        packet = np.array(packet.split())
        if packet[4] == 'ADwin' and packet[5] == 'Config':
            packet = np.delete(packet, 5)
        # add host to rest of output: 1) get host from tshark 2) get host from whois 3) host is ""
        # if len(packet) > 12:
        #     packet = np.append(packet[:12], ' '.join(packet[12:]))
        # else:
        #     packet = np.append(packet, '')
        # if len(packet) < 13 or len(packet[6])>=18:
        #     # print(packet)
        #     # for _ in range (11-len(packet)):
        #     #     packet = np.append(packet, 'NA')
        #     # result.append(packet)
        #     # # print(packet.size)
        #     continue
        
        # ip_src = packet[6]
        # ip_dst = packet[7]  # desintation host -> -e ip.dst
        # if utils.validate_ip_address(ip_src)==False or utils.validate_ip_address(ip_dst)==False:
        #     continue

        cur_time = packet[1]


        inv_mac_dic = {v: k for k, v in mac_dic.items()}
        if my_device_mac == packet[5]:  # dst = my device, inbound traffic
            to_dev_mac = packet[4]

        else:   # extract hostname for all outbound traffic
            to_dev_mac = packet[5]

        if to_dev_mac in inv_mac_dic: # known destination
            to_dev_name = inv_mac_dic[to_dev_mac]
        else:   # mutlicast/broadcast or unknown destination
            if addressing_method(to_dev_mac)==0:
                print('Unknown destination from %s:' % dev_name, to_dev_mac)
            to_dev_name = to_dev_mac
            # host = extract_host_new(ip_src, ip_dst, ip_host, count_dic, cur_time, whois_list)

        to_dev_name = to_dev_name.lower()
        packet = np.append(packet, to_dev_name) #append host as last column of output
        # if len(packet) < 14:
        #     print('Length incorrect! ', packet)
        #     continue
        # packet = np.asarray(packet)
        result.append(np.asarray(packet))
        # result = np.append(result, packet)
    result = np.asarray(result, dtype=object)
    # for i in result:
    #     print(i, addressing_method(i[5]))
    # exit(0)
    # print()
    if len(result) == 0:
        print('len(result) == 0')
        return 0


    return result



# TODO
# ! Bug, need to recreat all_packets_results instead of edit it 
def group_filter(dict_dec, all_packets_results, func, packet_index):
    new_all_packets_results = {}
    for device in all_packets_results:
        cur_packets = all_packets_results[device]['packets']
        new_packets = []
        for packet in cur_packets:
            # print(packet[packet_index], func.__name__)
            if func(packet[packet_index]):
                new_packets.append(packet)
        new_all_packets_results[device] = {'packets': new_packets}
        # new_all_packets_results[device]['packets'] = new_packets
    return new_all_packets_results

def BC_filter(dict_dec, all_packets_results):
    return group_filter(dict_dec, all_packets_results, is_broadcast, 5)

def MC_filter(dict_dec, all_packets_results):
    return group_filter(dict_dec, all_packets_results, is_multicast, 5)

def ipv6_filter(dict_dec, all_packets_results):
    return group_filter(dict_dec, all_packets_results, is_ipv6, 9)


def protocol_filter(dict_dec, all_packets_results, protocol):
    # ! TODO
    return 0 
    # # filter a group of protocols 
    # if protocol=='broadcast':
    #     return BC_filter(dict_dec, all_packets_results)
    # elif protocol=='multicast':
    #     return MC_filter(dict_dec, all_packets_results)
    # elif protocol=='ipv6':
    #     return ipv6_filter(dict_dec, all_packets_results)
    
    # # protocol filter 
    # protocol_lower = []
    # for i in protocol:
    #     protocol_lower.append(i.lower())
    # for device in dict_dec:
    #     if device not in all_packets_results:
    #         print('no device %s in protocol analysis' % device)
    #         # exit(1)
    #         continue
    #     cur_packets = all_packets_results[device]['packets']
    #     new_packets = []
    #     for packet in cur_packets:
    #         if packet[6].lower() not in protocol_lower:
    #             continue
    #         new_packets.append(packet)
    #     all_packets_results[device]['packets'] = new_packets

    # return all_packets_results


