from analyser.utils import *


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

def icmpv6_analysis():
    return 0