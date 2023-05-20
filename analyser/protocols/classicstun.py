from analyser.utils import *
def classicstun_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','classicstun')
    
    bind_request_count = {}
    share_request_count = {}
    other_count = {}
    # bind request: 1
    # share secret request: 2
    # classicstun.type == '257' # bind response
    # classicstun.type == '258' # share secret response
    mac_dic = read_mac_address()
    rev_mac_dict = {}
    for k,v in mac_dic.items():
        rev_mac_dict[v] = k
    for device in dict_dec:
        print('analyzing classic-stun packets...', device) # os.getpid()
        if device not in packets_dict:
            continue
        
        stun_dst = {}
        message = {}
        count = 0
        for packet in packets_dict[device]:
            # print(packet.classicstun)
            # exit(1)
            my_device_mac = mac_dic[device]
            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            stun_type = packet.classicstun.type
            # print(stun_type)
            if stun_type == '0x0001':
                bind_request_count[device] = bind_request_count.get(device, 0) + 1
            elif stun_type == '0x0002':
                share_request_count[device] = share_request_count.get(device, 0) + 1
            else:
                other_count[device] = other_count.get(device, 0) + 1
            if src_mac == my_device_mac:
                dst_dev = rev_mac_dict[dst_mac]
                stun_dst[dst_dev] = stun_dst.get(dst_dev, 0) + 1
                if packet.classicstun.length != '0x0000':
                    # print(packet.classicstun.length, packet.classicstun)
                    # message.append(packet.classicstun._all_fields)
                    message[stun_type] = message.get(stun_type, 0) + 1
            # count += 1
            # if count > 10000:
            #     break
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            sorted_stun_dst = sorted([(k,v) for k,v in stun_dst.items()], key=lambda t:t[1], reverse=True)
            
            for i in sorted_stun_dst:
                f.write('Dst %s: %d\n' % (i[0], i[1]))
            
            f.write('\n')
            # messages
            sorted_message = sorted([(k,v) for k,v in message.items()], key=lambda t:t[1], reverse=True)
            
            for i in sorted_message:
                f.write('Nonempty %s: %d\n' % (i[0], i[1]))

            
            
    count = 0 
    return_list = []
    for device in dict_dec:
        count += 1
        print(device, bind_request_count.get(device, 0), share_request_count.get(device, 0), other_count.get(device, 0))
        if (bind_request_count.get(device, 0) + share_request_count.get(device, 0) + other_count.get(device, 0)) == 0:
            continue
        return_list.append([device, bind_request_count.get(device, 0), share_request_count.get(device, 0), other_count.get(device, 0)])

    header = ['device', 'bind_request_count', 'share_request_count', 'other_count']
    return (header, return_list)

