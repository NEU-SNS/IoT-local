from analyser.flow_extraction import extract_single, burst_split
from analyser.utils import * 
from analyser.vis import * 
from . import plotting

def output_file_generator(out_dir:str, basename:str, device:str) -> str:
    tmp_dir = os.path.join(out_dir, basename)
    if not os.path.exists(tmp_dir):
        os.system('mkdir -pv %s' % tmp_dir)
    output_file = os.path.join(tmp_dir, device + '.txt') # Output file
    return output_file

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

def basic_analysis_output(model_dir, out_dir, dict_dec, all_packets_results):
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
        if device not in all_packets_results:
            print('No traffic during the time:', device)
            continue
        print('Processing traffic ', device)
        results = all_packets_results[device]['packets']
        if 'flows' in all_packets_results[device]:
            burst_dic = all_packets_results[device]['flows']
        else:
            burst_dic = {}
            
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
    unicast_size = 0
    multicast_size = 0
    broadcast_size = 0
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

    print('Unicast: packets %d, size %d' % (unicast_count, unicast_size))
    print('Multicast: packets %d, size %d' % (multicast_count, multicast_size))
    print('Broadcast: packets %d, size %d' % (broadcast_count, broadcast_size))

    # end

    return 0


def testing_generator():
    return 0