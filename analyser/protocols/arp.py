from analyser.utils import *

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
        # print(target_device)
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

