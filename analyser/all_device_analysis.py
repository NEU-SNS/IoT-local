# from analyser.flow_extraction import extract_single, burst_split
from analyser.utils import * 
from analyser.vis import * 
from . import plotting
"""
Trying to deprecate this file 
"""

def addressing_distribution(packets:list[str]) -> list[int]:
    output = [0,0,0]
    for packet in packets:
        tmp = addressing_method(packet[5])
        output[tmp] += 1
    return output

def meaningful_addressing_distribution(packets:list[str]) -> list[int]:
    """ Exclude router traffic 

    Args:
        packets (list[str]): _description_

    Returns:
        list[int]: _description_
    """
    output = [0,0,0]
    for packet in packets:
        if is_router(packet[4], packet[5]):
            continue
        # if 'DHCP' in packet[6]:
        #     continue 
        tmp = addressing_method(packet[5]) # dst mac
        output[tmp] += 1
    return output

def destination_distribution(packets:list[str]) -> int:
    output = set()
    for packet in packets:
        if is_broadcast(packet[5]) or is_multicast(packet[5]) or is_router(packet[4], packet[5]): # dst mac
            continue
        output.add(packet[-1])
    return len(output)

def basic_analysis_output(model_dir, out_dir, dict_dec, tmp_models_name):
    # TODO: refactor this part to simplify
    # * distribution output file:
    # tmp_basename = os.path.basename(out_dir)
    # model_file = model_dir+'/distribution_%s.model' % tmp_basename

    # if os.path.isfile(model_file):
    #     distribution_dicts = pickle.load(open(model_file, 'rb'))
    # else:
    #     distribution_dicts = {}

    # distribution_dicts = {}

    # # * initialization 
    # if 'addressing_method' in distribution_dicts:
    #     addressing_distribution_dict = distribution_dicts['addressing_method']
    # else:
    #     addressing_distribution_dict = {}
    # if 'destination' in distribution_dicts:
    #     destination_distribution_dict = distribution_dicts['destination']
    # else:
    #     destination_distribution_dict = {}
    
    
    addressing_distribution_dict = {}
    destination_distribution_dict = {} # how many devices each device talk with
    meaningful_addressing_distribution_dict = {}

    # * overall protocol stats
    protocol_distribution_overall = {} # {protocol: {device: # of packets}}
    # unicast multicast broadcast: 
    protocol_distribution_per_addressing_method = [{},{},{}] # 0: unicast, 1: multicast, 2: broadcast

    reached_device_distribution_dict = {} # how many devices talk with each device 

    # * loop through
    for device in dict_dec: 
        # if device in addressing_distribution_dict and device in destination_distribution_dict: #  and not device.startswith('google-'):
        #     continue
        packets_file = os.path.join(model_dir, device, '%s.model' % tmp_models_name)
        if not os.path.isfile(packets_file):
            print('No %s traffic in this dataset:' % device)
            continue
        packets_results = pickle.load(open(packets_file, 'rb'))
        # if device not in all_packets_results:
            
        print('Processing traffic ', device)
        results = packets_results['packets']
        # if 'flows' in packets_results:
        #     burst_dic = packets_results['flows']
        # else:
        #     burst_dic = {}
            
        # * addressing method by packets
        addressing_distribution_dict[device] = addressing_distribution(results) # num of packets per addressing method
        meaningful_addressing_distribution_dict[device] = meaningful_addressing_distribution(results) 

        # * number of contacted devices for each device
        destination_distribution_dict[device] = destination_distribution(results) 

    
        

        # * packet count per Protocol 
        packet_count = {} # key: dst device, value: dict {protocol, number of packets}
        protocol_by_packet = {} 
        protocol_by_size = {} 

        for packet in results:
            # * overall
            if packet[6] not in protocol_distribution_overall:
                protocol_distribution_overall[packet[6]] = {}
            if device not in protocol_distribution_overall[packet[6]]:
                protocol_distribution_overall[packet[6]][device] = 0
            protocol_distribution_overall[packet[6]][device] += 1

            if packet[6] not in protocol_distribution_per_addressing_method[addressing_method(packet[5])]:
                protocol_distribution_per_addressing_method[addressing_method(packet[5])][packet[6]] = {}
            if device not in protocol_distribution_per_addressing_method[addressing_method(packet[5])][packet[6]]:
                protocol_distribution_per_addressing_method[addressing_method(packet[5])][packet[6]][device] = 0
            protocol_distribution_per_addressing_method[addressing_method(packet[5])][packet[6]][device] += 1

            # * per device
            if packet[-1] not in packet_count:
                packet_count[packet[-1]] = {}
            if packet[6] not in packet_count[packet[-1]]:
                packet_count[packet[-1]][packet[6]] = 0
            packet_count[packet[-1]][packet[6]] += 1

            if packet[6] not in protocol_by_packet:
                protocol_by_packet[packet[6]] = 0
                protocol_by_size[packet[6]] = 0
            protocol_by_packet[packet[6]] += 1
            protocol_by_size[packet[6]] += int(packet[3])

        """
        # * Distribution of protocol by number of packets
        plotting.plotting_bar(protocol_by_packet, os.path.join(out_dir, 'vis', 'device' , device ,'packets') , '# of packets per protocol')

        # * Distribution of protocol by total size in one day 
        plotting.plotting_bar(protocol_by_size, os.path.join(out_dir, 'vis', 'device', device ,'size') , 'total bytes on Aug 25 per protocol')
        

        # * write output logs
        packet_count_dir = os.path.join(out_dir, 'packet_count')
        output_file = os.path.join(packet_count_dir ,device + '.txt') # Output file
        if not os.path.exists(packet_count_dir):
            os.system('mkdir -pv %s' % packet_count_dir)
        outputs = packet_count
        with open(output_file, 'w') as ff:
            for k,v in sorted(outputs.items()):
                ff.write(('%s\n') % k)
                reached_device_distribution_dict[k] = reached_device_distribution_dict.get(k, 0) + 1
                # print(k)
                for k2 in v:
                    ff.write(('  %s, %d\n') % ( k2, v[k2]))
                    # print('  ', k2, v[k2])
                ff.write(('\n'))
        
        """
        '''
        # * by flows
        flow_count = {} # key: device, value: dict {protocol, number of packets}
        protocol_by_flow = {} 
        protocol_by_flow_size = {} 

        for five_tuple in burst_dic:
            for flow_ts in burst_dic[five_tuple]:
                cur_flow = burst_dic[five_tuple][flow_ts]
                packet = cur_flow[0]
                # flow_length = len(cur_flow)
                if packet[-1] not in flow_count:
                    flow_count[packet[-1]] = {}
                if packet[6] not in flow_count[packet[-1]]:
                    flow_count[packet[-1]][packet[6]] = 0
                flow_count[packet[-1]][packet[6]] += 1

                if packet[6] not in protocol_by_flow:
                    protocol_by_flow[packet[6]] = 0
                    protocol_by_flow_size[packet[6]] = []
                protocol_by_flow[packet[6]] += 1

                flow_size = 0
                for tmp_p in cur_flow:
                    flow_size += int(packet[3])
                protocol_by_flow_size[packet[6]].append(flow_size)
        # * Distribution of protocol by number of flows
        plotting.plotting_bar(protocol_by_flow, os.path.join(out_dir, 'vis', 'device' , device ,'flows') , '# of flows per protocol')

        # * Distribution of protocol by average flow size (with std)
        # ! seems to have bugs 
        plotting.plotting_mean_bar(protocol_by_flow_size, os.path.join(out_dir, 'vis', 'device' , device ,'flow_size') , 'Average flow size per protocol')
        
        '''
        
        """
        For graph visualization, run graph_generator.py after this. 
        """
        # * tcp vis output 
        output_file = output_file_generator(out_dir, 'tcp_output', device)

        tcp_output = tcp_vis(results)
        with open(output_file, 'w') as ff:
            for k,v in sorted(tcp_output.items()):
                ff.write(('%s %d\n') % (k, v))

        # * udp vis output 
        output_file = output_file_generator(out_dir, 'udp_output', device)

        udp_output = udp_vis(results)
        with open(output_file, 'w') as ff:
            for k,v in sorted(udp_output.items()):
                ff.write(('%s %d\n') % (k, v))

    return 0

    # ! All of things below are reimplemented in protocol_identification.py

    # * save distribution results 
    # distribution_dicts = {'addressing_method': addressing_distribution_dict,
    #                         'destination': destination_distribution_dict}
    # print(model_file)
    # pickle.dump(distribution_dicts, open(model_file, 'wb'))

    # TODO * devices per protocol:
    # protocol_distribution_overall

    # * num of devices per protocol 
    if not os.path.exists(os.path.join(out_dir, 'vis')):
        os.system('mkdir -pv %s' % os.path.join(out_dir, 'vis'))
        
    with open(os.path.join(out_dir, 'vis', 'device_per_protcol.txt'), 'w') as ff:
        for k,v in sorted(protocol_distribution_overall.items()):
            ff.write(('%s: %d, %s\n') % (k, len(v), v))
    
    protocol_distribution_device_num = {x: len(protocol_distribution_overall[x]) for x in protocol_distribution_overall}
    plotting.plotting_bar(protocol_distribution_device_num, os.path.join(out_dir, 'vis', 'device_per_protcol') , '# of devices per protocol')
    # * num of packets per protocol
    protocol_distribution_packet_num = {}
    for x in protocol_distribution_overall:
        protocol_distribution_packet_num[x] = {}
        tmp_count = 0
        for y in protocol_distribution_overall[x]:
            tmp_count += protocol_distribution_overall[x][y]
        protocol_distribution_packet_num[x] = tmp_count
    plotting.plotting_bar(protocol_distribution_packet_num, os.path.join(out_dir, 'vis', 'packet_per_protcol') , '# of packets per protocol')

    # * num of device per protocol per addressing method: 
    unicast_tmp = protocol_distribution_per_addressing_method[0]
    multicast_tmp = protocol_distribution_per_addressing_method[1]
    broadcast_tmp = protocol_distribution_per_addressing_method[2]

    unicast_count = 0
    for x in unicast_tmp:
        for y in unicast_tmp[x]:
            unicast_count += unicast_tmp[x][y]
    multicast_count = 0
    for x in multicast_tmp:
        for y in multicast_tmp[x]:
            multicast_count += multicast_tmp[x][y]
    broadcast_count = 0
    for x in broadcast_tmp:
        for y in broadcast_tmp[x]:
            broadcast_count += broadcast_tmp[x][y]
    
    # # unicast:
    unicast_tmp_distribution = {x: len(unicast_tmp[x]) for x in unicast_tmp}
    plotting.plotting_bar(unicast_tmp_distribution, os.path.join(out_dir, 'vis', 'device_per_protcol_unicast') , '# of devices per protocol (unicast only)')
    # # multicast
    multicast_tmp_distribution = {x: len(multicast_tmp[x]) for x in multicast_tmp}
    plotting.plotting_bar(multicast_tmp_distribution, os.path.join(out_dir, 'vis', 'device_per_protcol_multicast') , '# of devices per protocol (multicast only)')
    # # broadcast
    broadcast_tmp_distribution = {x: len(broadcast_tmp[x]) for x in broadcast_tmp}
    plotting.plotting_bar(broadcast_tmp_distribution, os.path.join(out_dir, 'vis', 'device_per_protcol_broadcast') , '# of devices per protocol (broadcast only)')



    # * all devices plotting 

    # num of dst per device  
    plotting.plotting_bar(destination_distribution_dict, os.path.join(out_dir, 'vis', 'destination') , '# of contacted destination per device')
    # number of devices reach the destination
    plotting.plotting_bar(reached_device_distribution_dict, os.path.join(out_dir, 'vis', 'contacted_device') , '# of contacted device per destination')
    
    # num of packets per addressing method per device 
    plotting.plotting_multicolumn_bar(addressing_distribution_dict, os.path.join(out_dir, 'vis', 'addressing_method_log'), '# of packet per addressing method per device')

    # num of packets per addressing method per device but exclude traffic to/from the router. 
    plotting.plotting_multicolumn_bar(meaningful_addressing_distribution_dict, os.path.join(out_dir, 'vis', 'addressing_method_log_meaningful'), '# of packet (exclude traffic to/from router) per addressing method per device')

    # num of packets per addressing method per device but it's stacked bar chart without log scale
    plotting.plotting_stacked_bar(addressing_distribution_dict, os.path.join(out_dir, 'vis', 'addressing_method_stacked'), '# of packet per addressing method per device')

    # num of unicast packets per device excluding traffic to/from the router. 
    unicast_distribution_dict = {x:meaningful_addressing_distribution_dict[x][0] for x in meaningful_addressing_distribution_dict}
    plotting.plotting_bar(unicast_distribution_dict, os.path.join(out_dir, 'vis', 'unicast_distribution_dict') , '# of unicast packet per device')
    # unicast_size = 0
    # multicast_size = 0
    # broadcast_size = 0
    # for x in meaningful_addressing_distribution_dict:
    #     unicast_size += meaningful_addressing_distribution_dict[x][0]
    #     multicast_size += meaningful_addressing_distribution_dict[x][1]
    #     broadcast_size += meaningful_addressing_distribution_dict[x][2]

    # num of multicast packets per device excluding traffic to/from the router. 
    multicast_distribution_dict = {x:meaningful_addressing_distribution_dict[x][1] for x in meaningful_addressing_distribution_dict} 
    plotting.plotting_bar(multicast_distribution_dict, os.path.join(out_dir, 'vis', 'multicast_distribution_dict') , '# of multicast packet per device')
    # num of broadcast packets per device excluding traffic to/from the router. 
    broadcast_distribution_dict = {x:meaningful_addressing_distribution_dict[x][2] for x in meaningful_addressing_distribution_dict} 
    plotting.plotting_bar(broadcast_distribution_dict, os.path.join(out_dir, 'vis', 'broadcast_distribution_dict') , '# of broadcast packet per device')

    print('Unicast: packets %d' % (unicast_count))
    print('Multicast: packets %d' % (multicast_count))
    print('Broadcast: packets %d' % (broadcast_count))

    # end

    return 0



def idle_inputs(dict_dec:dict, model_dir:str, model_file_name:str, pcap_filter:str)->dict:
    """_summary_

    Args:
        dict_dec (dict): _description_
        model_dir (string): _description_
    Returns:
        dict: 
    """

    
    # all_packets_results = {}
    # * process each device: 
    for device in dict_dec:

        packet_dir = os.path.join(model_dir, device)
        if not os.path.exists(packet_dir):
            os.system('mkdir -pv %s' % packet_dir)
        packets_file = packet_dir+'/%s.model' % model_file_name
        print(packets_file)
        if os.path.isfile(packets_file):
            print('reading')
            # packets_results = pickle.load(open(packets_file, 'rb'))
            continue
        else:
            packets_results = {}
        # if 'packets' in packets_results: #  and 'flows' in packets_results:
        #     # all_packets_results[device] = packets_results
        #     # pickle.dump(packets_results, open(packets_file, 'wb'))
        #     continue
        # else:
        #     # print(packets_results.keys())
        packets_original = {}
        packets_in_flows = {}
        # exit(1)
        # print(len(packets_original), len(packets_in_flows))
        # * extract features from PCAP files 
        
        results = []
        # results = {}
        print(device, dict_dec[device])
        for pcap_file in dict_dec[device]:
            tmp_res = extract_pcap_command_line(pcap_file, pcap_filter)
            if isinstance(tmp_res, int):
                continue
            # print(tmp_res.shape)
            # try:
            for tmp in tmp_res:
                results.append(tmp)
                # if len(tmp_res.shape) != 1:
                #     results = np.concatenate((results, tmp_res), axis=0) 
                # else: 
                #     results = np.concatenate((results, tmp_res.reshape(tmp_res.shape,1)), axis=0) 
            # except:
            #     print(device, 'failed!!!!! ', tmp_res.shape)
            #     print(tmp_res)
            #     continue

        if len(results) == 0 or len(results) == 1:
            print('Result==0')
            continue
        packets_original = results
        # print('Len packets_original:', len(packets_original))

        # TODO retransmisson
        try:
            flow_dic = extract_single(results)
            # print('len(flow_dic):', len(flow_dic))
            burst_threshold = 1
            burst_dic = burst_split(flow_dic, burst_threshold)
            if len(burst_dic) == 0:
                print('burst_dic==0')
                continue
            packets_in_flows = burst_dic
        except Exception as e:
            print(device, 'failed!!!!! ')
            print(str(e))
            continue

        # print('Len packets_in_flows:', len(packets_in_flows))
        packets_results = {'packets': packets_original, 'flows': packets_in_flows}
        # all_packets_results[device] = packets_results
        # print('dumping')
        pickle.dump(packets_results, open(packets_file, 'wb'))

    return 0


def extract_pcap_command_line(pcap_file:str, pcap_filter:str) -> list[list[str]]:
    """extract features from a pcap file
    
    Args:
        pcap_file (_type_): PCAP file 

    Returns:
        list[list[str]]: list of packets
    """
    global mac_dic, inv_mac_dic
    dev_name = pcap_file.split('/')[-2]

    feature_header = ['number', 'time_epoch', 'time_delta', 'len (size)', 'src mac', 'dst mac', 'Protocol', 'layer 4 protocol code (optional)', 
                    'TCP/UDP stream (optional)', 'src ip (optional)', 'dst ip (optional)', 'src port (optional)', 'dst port (optional)']

    command = ["tshark", "-r", pcap_file, 
                "-Y", pcap_filter,
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
    
    for packet in filter(None, out.decode('utf-8').split('\n')):
        packet = np.array(packet.split())
        if packet[4] == 'ADwin' and packet[5] == 'Config':
            packet = np.delete(packet, 5)

        cur_time = packet[1]

        
        if my_device_mac == packet[5]:  # dst = my device, inbound traffic
            to_dev_mac = packet[4]

        else:   # extract destination for all outbound traffic
            to_dev_mac = packet[5]

        if to_dev_mac in inv_mac_dic: # known destination
            to_dev_name = inv_mac_dic[to_dev_mac]
        else:   # mutlicast/broadcast or unknown destination
            if addressing_method(to_dev_mac)==0 and not to_dev_mac.startswith('02:') and not to_dev_mac.startswith('00:'):
                print('Unknown destination from %s:' % dev_name, to_dev_mac)
            to_dev_name = to_dev_mac
            # host = extract_host_new(ip_src, ip_dst, ip_host, count_dic, cur_time, whois_list)

        to_dev_name = to_dev_name.lower()
        packet = np.append(packet, to_dev_name) #append host as last column of output

        result.append(np.asarray(packet))
        # result = np.append(result, packet)
    result = np.asarray(result, dtype=object)

    if len(result) == 0:
        print('len(result) == 0')
        return 0

    return result



def testing_generator():
    return 0