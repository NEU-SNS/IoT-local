from analyser.utils import *
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
