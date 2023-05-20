from analyser.utils import *

def tplink_smarthome_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','tplink-smarthome')
    
    mac_dic = read_mac_address()
    rev_mac_dict = {}
    for k,v in mac_dic.items():
        rev_mac_dict[v] = k
    
    get_sysinfo_count = {}
    other_count = {}
    udp_count = {}
    tcp_count = {}
    cmd_count = {}
    rsp_count = {}
    for device in dict_dec:
        print('analyzing classic-stun packets...', device) # os.getpid()
        if device not in packets_dict:
            continue
        
        
        message = {}
        sent_tcp = 0
        sent_udp = 0
        sent_udp_broadcast = 0
        received_tcp = 0
        received_udp = 0
        count = 0
        for packet in packets_dict[device]:
            # print(packet.classicstun)
            # exit(1)
            my_device_mac = mac_dic[device]
            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            
            transport_layer_protocol = packet.ip.proto
            if transport_layer_protocol == '17':
                udp_count[device] = udp_count.get(device, 0) + 1
                
                if src_mac == my_device_mac:
                    sent_udp += 1
                    if is_broadcast(dst_mac):
                        sent_udp_broadcast += 1
                else:
                    received_udp += 1
            elif transport_layer_protocol == '6':
                tcp_count[device] = tcp_count.get(device, 0) + 1
                if src_mac == my_device_mac:
                    sent_tcp += 1
                else:
                    received_tcp += 1
                    
            else:
                # ICMP
                continue
            
            

            json_path = packet['tplink-smarthome'].json_path
            
            if len(json_path.split('/')) > 3:
                cur_command = json_path.split('/')[2]
                rsp_count[device] = rsp_count.get(device, 0) + 1

            elif len(json_path.split('/')) == 3:
                cur_command = json_path.split('/')[2]
                cmd_count[device] = cmd_count.get(device, 0) + 1
                
            else:
                cur_command = json_path

                
            if 'get_sysinfo' in cur_command:
                get_sysinfo_count[device] = get_sysinfo_count.get(device, 0) + 1
            else:
                other_count[device] = other_count.get(device, 0) + 1
                message[cur_command] = message.get(cur_command, 0) + 1

        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        if (sent_tcp + sent_udp + received_tcp+ received_udp) == 0:
            continue
        with open(out_file, 'w') as f:
            f.write('Sent TCP: %d\n' % (sent_tcp))
            f.write('Sent UDP: %d\n' % (sent_udp))
            f.write('Sent UDP Broadcast: %d\n' % sent_udp_broadcast)
            f.write('Received TCP: %d\n' % (received_tcp))
            f.write('Received UDP: %d\n' % (received_udp))
            
            sorted_message = sorted([(k,v) for k,v in message.items()], key=lambda t:t[1], reverse=True)
            
            for i in sorted_message:
                f.write('json path: %s | %d\n' % (i[0], i[1]))
         

            
            
    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, get_sysinfo_count.get(device, 0), other_count.get(device, 0), udp_count.get(device, 0), tcp_count.get(device, 0), cmd_count.get(device, 0), rsp_count.get(device, 0))
        if (get_sysinfo_count.get(device, 0)+ other_count.get(device, 0)) == 0:
            continue
        return_list.append([device, get_sysinfo_count.get(device, 0), other_count.get(device, 0), udp_count.get(device, 0), tcp_count.get(device, 0), cmd_count.get(device, 0), rsp_count.get(device, 0)])

    header = ['device', 'get_sysinfo_count', 'other_count', 'udp_count', 'tcp_count', 'cmd_count', 'rsp_count']
    return (header, return_list)

        
    