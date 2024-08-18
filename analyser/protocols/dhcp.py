from analyser.utils import *

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
        vendor_class_id = set()
        device_hostname = set()
        dhcp_type = {}
        option_set = set()
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
            
            tmp_all_fields = packet.dhcp._all_fields
            
            for options in tmp_all_fields:
                if options.strip().startswith('dhcp.option.'):
                    option_set.add(options.strip())
            # if len(device_hostname) == 0:
            if 'dhcp.option.hostname' in tmp_all_fields:
            # try:
                device_hostname.add(packet.dhcp.option_hostname)
                    
            # if len(vendor_class_id) == 0:
            if 'dhcp.option.vendor_class_id' in tmp_all_fields:
            # try:
                vendor_class_id.add(packet.dhcp.option_vendor_class_id)
                # except:
                #     continue
        # write outputs for each device
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        with open(out_file, 'w') as f:
            f.write('Parameter Request List: \n')
            for p in request_info:
                f.write(p)
                f.write('\n')
            f.write('DHCP Option List: \n')
            for o in option_set:
                f.write(o)
                f.write('\n')
            if len(device_hostname) != 0:
                f.write('Host Name: ')
                for dd in device_hostname: 
                    f.write('%s\n' % dd)
            if len(vendor_class_id) != 0:
                f.write('Vendor class identifier: ')
                for vv in vendor_class_id:
                    f.write('%s\n' % vv)
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

