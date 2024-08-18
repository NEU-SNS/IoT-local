import os 

"""
BCMC protocols per device 
"""
file_dir = "/home/hutr/local_output/idle-dataset-dec/bcmc/bcmc/new_packet_count"

dev_protocol_dict = {}
for dev_file in os.listdir(file_dir):
    if not dev_file.endswith('.txt'):
        continue
    device_name  = dev_file.split('.')[0]
    with open(os.path.join(file_dir,dev_file), 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line and line.startswith(' '):
                tmp_protocol = line.strip().split(',')[0]
                if tmp_protocol in ['arp', 'basicxid', 'llc', 'dhcp', 'dhcpv6', 'icmp', 'icmpv6', 'igmp', 'igmpv2', 'igmpv3']:
                    continue
                if device_name not in dev_protocol_dict:
                    dev_protocol_dict[device_name] = set()
                dev_protocol_dict[device_name].add(tmp_protocol)
count = 0 
sorted_dev_protocol_dict = dict(sorted(dev_protocol_dict.items(), key=lambda x: len(x[1]), reverse=True))
for k, v in sorted_dev_protocol_dict.items():
    if len(v)==0:
        continue
    count+=1
    print(f"{k}: {len(v)}: {v}")
print('Count:',count)    