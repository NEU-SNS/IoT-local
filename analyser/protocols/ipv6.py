import os
import json


def parse_ipv6_logfiles(out_dir):
    print('parsing ipv6 output')
    cur_out_dir = os.path.join(out_dir, 'protocols','ipv6/')
    out_file = os.path.join(out_dir, 'protocols','ipv6_info.txt')
    if not os.path.isdir(cur_out_dir):
        print('Parse ipv6: Not a dir ', cur_out_dir)

    ipv6_protocol_count = {}
    for dev_file in os.listdir(cur_out_dir):
        if not dev_file.endswith('.txt'):
            continue
        print(dev_file)
        dev_name = dev_file.split('.')[0]
        with open(os.path.join(cur_out_dir,dev_file)) as f:
            lines = f.readlines()
            count = 0
            for line in lines:
                if line!='\n' or line!="":
                    if dev_name not in ipv6_protocol_count:
                        ipv6_protocol_count[dev_name] = {}
                    count += 1
                    tmp_prot = line.split(':')[0].strip()
                    packet_count = line.split(':')[1].strip()
                    ipv6_protocol_count[dev_name][tmp_prot] = packet_count
        
    # print(request_info_list)
    with open(out_file, 'w') as f:
        # ordered_ipv6_address_count = []
        # for k,v in ipv6_protocol_count.items():
        #     # print(k.strip(),':', v)
        #     ordered_ipv6_address_count.append([k,v])
        # ordered_ipv6_address_count = sorted(ordered_ipv6_address_count, key=lambda t: t[1],reverse=True)
        # for i in ordered_ipv6_address_count:
        #     f.write('%s: %d\n' %(i[0].strip(), i[1]))
        for dev, v in ipv6_protocol_count.items():
            f.write('%s\n' % dev )
            for prot, count in v.items():
                f.write(' %s: %s\n' % (prot, count))
            f.write('\n')
            
out_dir = '/home/hutr/local_output/idle-dataset-dec'
parse_ipv6_logfiles(out_dir)