from analyser.utils import *
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


def dhcpv6_analysis(packet):
    if packet.eth.dst.split(':')[-1] != '3' or packet.eth.dst.split(':')[-2] != '1':
        # print('Wrong DHCPv6 multicast group')
        return 1
    else:
        return 0
    


def mdns_packet_analysis(packet):
    if packet.eth.dst.split(':')[-1] != 'fb':
        print('Wrong MDNS multicast group')
        return 1
    else:
        return 0

