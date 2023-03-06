import os
import csv
import pandas as pd
import json
"""This file parse the files in flow_burst
"""

def parse_flow_burst(out_dir):
    print('parsing flow bursts')
    cur_out_dir = os.path.join(out_dir, 'flow_burst/')
    csv_out_dir = os.path.join(out_dir, 'port_info/')
    if not os.path.exists(csv_out_dir):
            os.system('mkdir -pv %s' % csv_out_dir)
    out_file = os.path.join(cur_out_dir,'_protocol_port_info.json')
    if not os.path.isdir(cur_out_dir):
        print('Parse flow burst: Not a dir ', cur_out_dir)

    protocol_port_dict = {}     # {device: {protocol: [device_port, dst_port]}}
    server_port_dict = {} # {device: {protocol: [device_port (only inbound)]}}
    # device_protocol_port_dict = {}     # {device: {dst_device: {protocol: {(device_port, dst_port): {direction: [packet_num, volume]} }}}
    # device_protocol_port_dict2 = {}     # {(device, device_port, dst_device, dst_port, protocol, direction): [packet_num, volume]}
    for dev_file in os.listdir(cur_out_dir):
        if not dev_file.endswith('.csv'):
            continue
        print(dev_file)
        dev_name = dev_file.split('.')[0]
        protocol_port_dict[dev_name] = {}
        server_port_dict[dev_name] = {}
        # device_protocol_port_dict[dev_name] = {}
        with open(os.path.join(cur_out_dir,dev_file)) as f:
            lines = csv.reader(f)
            count = 0
            for line in lines:
                if len(line)==0 or count==0:
                    count += 1
                    continue
                
                protocol = line[1]
                dst_device = line[2]
                device_port = line[3]
                dst_port = line[4]
                flow_length = line[5]
                volume = line[6]
                inbound = line[-1]
                if protocol not in protocol_port_dict[dev_name]:
                    protocol_port_dict[dev_name][protocol] = set()
                protocol_port_dict[dev_name][protocol].add((device_port, dst_port))
                
                if inbound:
                    if protocol not in server_port_dict[dev_name]:
                        server_port_dict[dev_name][protocol] = set()
                    server_port_dict[dev_name][protocol].add(device_port)
        
        # print(protocol_port_dict)
        # testing pandas df
        df = pd.read_csv(os.path.join(cur_out_dir,dev_file))
        # print(df.columns)
        df = df.drop(columns=['timestamp'])
        df.rename({'my_port': 'device_port', 'others_port': 'dst_port', 'flow_length': 'packet_count'}, axis=1, inplace=True)
        new_df = df.groupby(['protocol','dst','device_port','dst_port','inbound']).sum()
        # new_df.rename({'my_port': 'device_port', 'others_port': 'dst_port', 'flow_length': 'packet_count'}, axis=1, inplace=True)
        
        csv_out_file = os.path.join(csv_out_dir,'%s.csv' % dev_name)
        # print(new_df.head())
        # print(new_df.columns)
        # exit(1)
        new_df.to_csv(csv_out_file)
        # break
    
    for dev_name in protocol_port_dict:
        for protocol in protocol_port_dict[dev_name]:
            protocol_port_dict[dev_name][protocol] = list(protocol_port_dict[dev_name][protocol])
            # print(dev_name, protocol, len(list(protocol_port_dict[dev_name][protocol])))
    
    for dev_name in server_port_dict:
        for protocol in server_port_dict[dev_name]:
            server_port_dict[dev_name][protocol] = list(server_port_dict[dev_name][protocol])
            print(dev_name, protocol, len(server_port_dict[dev_name][protocol]))
    # print(request_info_list)
    
    with open(out_file, 'w') as f:
        
        f.write(json.dumps(protocol_port_dict, indent=4))
        # f.write('\n\n')
        # f.write(json.dumps(client_id, indent=4)
        
    out_file2 = os.path.join(cur_out_dir,'_server_protocol_port_info.json')
    with open(out_file2, 'w') as f:
        f.write(json.dumps(server_port_dict, indent=4))
        

out_dir = '/home/hutr/local_output/idle-dataset-dec-new'
parse_flow_burst(out_dir)