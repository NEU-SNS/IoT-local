import os
# import networkx as nx
# import matplotlib
# import matplotlib.pyplot as plt
# from matplotlib.colors import ListedColormap
# import pygraphviz
# import pydot
# from networkx.drawing.nx_agraph import graphviz_layout
# matplotlib.use('Agg')

# Define the paths to the two folders containing the TXT files
tcp_folder_path = '/home/hutr/local_output/idle-dataset-dec-new/tcp_output_cr'
udp_folder_path = '/home/hutr/local_output/idle-dataset-dec-new/udp_output_cr'
device_file = '/home/hutr/local-traffic-analysis/local-devices.txt'
device_file_formal = '/home/hutr/local-traffic-analysis/local-devices-formal-name.txt'


def output_data(out_file: str, device_pairs_list, single_node_list) -> int:
    # print('output:', out_file, device_pairs_list)
    # 
    with open(out_file, 'w') as of:

        # write header
        with open('connectedGraph/template-header.html') as hf:
            header = hf.read()
            of.write(header)

        device_list_formal = {}
        with open(device_file_formal) as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                device_list_formal[line.split(' ')[0]] = " ".join(line.split(' ')[1:])
        print(device_list_formal)
        for i in range(len(device_pairs_list)):
            device_pairs_list[i][0] = device_list_formal[device_pairs_list[i][0]]
            device_pairs_list[i][1] = device_list_formal[device_pairs_list[i][1]]
        for i in range(len(single_node_list)):
            single_node_list[i] = device_list_formal[single_node_list[i]]
        nodes = set()
        for dev1, dev2, protocol in device_pairs_list:
        
            nodes.add(dev1)
            nodes.add(dev2)
        for d in single_node_list:
            nodes.add(d)
        # # Iterate through the top-level devices and add missing devices they talk to
        # children = []
        # for parent in nodes:
        #     for child in dict_dec[parent].keys():
        #         if child not in children and child not in nodes:
        #             children.append(child)
        # nodes.extend(children)
        # Generate the text list of nodes
        node_colors = {}
        for dev in nodes:
            if 'Echo' in dev or 'Fire' in dev or 'Amazon' in dev:
                node_colors[dev] = '#00eaff'
            elif 'Google' in dev or 'Nest' in dev:
                node_colors[dev] =  '#ffa600'
            elif 'Apple' in dev or 'HomePod' in dev:
                node_colors[dev] = '#292627'
        nodes = list(nodes)
        for i in range(len(nodes)):
            dev = nodes[i]
            color = node_colors.get(dev, '#c5d7f0') # '#D2E5FF')
            of.write('        nodes.add([{id: "%s", label: "%s", shape: "dot", color:  { border: "#2B7CE9", background: "%s", highlight: { order: "#2B7CE9", background: "#D2E5FF"}}, size: 8, font: "18 Helvetica #050404"}]);\n' % (dev, dev, color))
        of.write('\n')
        
        edge_colors = {'TCP': '#03adfc', 'UDP': '#03adfc', 'Both': '#3165de'}
        edge_width = {'TCP': 1, 'UDP': 1, 'Both': 4}
        edge_dashes = {'TCP': 'false', 'UDP': 'true', 'Both': 'false'}
        # write edges:
        for i in range(len(device_pairs_list)):
            dev = device_pairs_list[i][0]
            dst_device = device_pairs_list[i][1]
            cur_protocol = device_pairs_list[i][2]
            # for j in range(len(dst_list)):
            #     dst_device = list(dst_list.keys())[j]
            #     dst_volume = dst_list[dst_device]
            # color = edge_colors.get(cur_protocol, 'black')
            width = edge_width.get(cur_protocol, 1)
            dashes = edge_dashes.get(cur_protocol, 'false')
            of.write('        edges.add([{from: "%s", to: "%s", width: %f, dashes: %s, color: { opacity : 0.65}}]);\n' % (
                dev, dst_device, width, dashes)) # color 
        of.write('\n') # color: "%s",

        # write footer
        with open('connectedGraph/template-footer.html') as ff:
            footer = ff.read()
            of.write(footer)

    return 0

# Define a function to read the contents of a TXT file and return a set of device names
def read_txt_file(filepath):
    with open(filepath) as f:
        lines = f.readlines()
    return set([line.strip().split()[0] for line in lines])

device_list = []
with open(device_file) as f:
    lines = f.readlines()
    for line in lines:
        device_list.append(line.strip() )
# print(device_list)
# Create a dictionary to store the set of devices for each TXT file
devices_dict = {}
devices_has_traffic = set()

# cluters
dict_echo = {}
dict_google = {}
dict_apple = {}
    


# Read the TXT files in the TCP folder and store the device sets in the devices_dict
for filename in os.listdir(tcp_folder_path):
    if filename.endswith('.txt'):
        filepath = os.path.join(tcp_folder_path, filename)
        devices_set = read_txt_file(filepath)
        device_name = filename.split('.')[0]
        for dev in devices_set:
            if dev in device_list:
                devices_has_traffic.add(dev)
                devices_has_traffic.add(device_name)
                device_pair = tuple(sorted([device_name, dev]))
                if device_pair not in devices_dict:
                    devices_dict[device_pair] = set()
                devices_dict[device_pair].add('TCP')
            
            # clusters:
            if 'echo' in device_name or 'echo' in dev or 'fire' in device_name or 'fire' in dev:
                if device_pair not in dict_echo:
                    dict_echo[device_pair] = set()
                dict_echo[device_pair].add('TCP')
            if 'google' in device_name or 'google' in dev or 'nest' in device_name or 'nest' in dev:
                if device_pair not in dict_google:
                    dict_google[device_pair] = set()
                dict_google[device_pair].add('TCP')
            if 'apple' in device_name or 'apple' in dev or 'homepod' in device_name or 'homepod' in dev:
                if device_pair not in dict_apple:
                    dict_apple[device_pair] = set()
                dict_apple[device_pair].add('TCP')
                

# Read the TXT files in the UDP folder and update the device sets in the devices_dict
for filename in os.listdir(udp_folder_path):
    if filename.endswith('.txt'):
        filepath = os.path.join(udp_folder_path, filename)
        devices_set = read_txt_file(filepath)
        device_name = filename.split('.')[0]
        for dev in devices_set:
            if dev in device_list:
                devices_has_traffic.add(dev)
                devices_has_traffic.add(device_name)
                device_pair = tuple(sorted([device_name, dev]))
                if device_pair not in devices_dict:
                    devices_dict[device_pair] = set()
                devices_dict[device_pair].add('UDP')
            
            # clusters:
            if 'echo' in device_name or 'echo' in dev:
                if device_pair not in dict_echo:
                    dict_echo[device_pair] = set()
                dict_echo[device_pair].add('UDP')
            if 'google' in device_name or 'google' in dev or 'nest' in device_name or 'nest' in dev:
                if device_pair not in dict_google:
                    dict_google[device_pair] = set()
                dict_google[device_pair].add('UDP')
            if 'apple' in device_name or 'apple' in dev or 'homepod' in device_name or 'homepod' in dev:
                if device_pair not in dict_apple:
                    dict_apple[device_pair] = set()
                dict_apple[device_pair].add('UDP')

single_node_list = []
for dev in device_list:
    if dev not in devices_has_traffic:
        single_node_list.append(dev)
# Create a set of unique device pairs and their corresponding protocol
device_pairs_list = []
for device_pair, trans_protocol in devices_dict.items():
    protocol = 'Both' if len(trans_protocol)==2 else list(trans_protocol)[0]
    device_pairs_list.append([device_pair[0], device_pair[1], protocol])
    

# out_file = os.path.join(out_dir, os.path.basename(in_dir) + '.html')
output_data('connectedGraph/test-new-cr.html', device_pairs_list, single_node_list) # 


# clusters:
device_pairs_list = []
for device_pair, trans_protocol in dict_echo.items():
    protocol = 'Both' if len(trans_protocol)==2 else list(trans_protocol)[0]
    device_pairs_list.append([device_pair[0], device_pair[1], protocol])
output_data('connectedGraph/test-echo-cr.html', device_pairs_list, []) # 

device_pairs_list = []
for device_pair, trans_protocol in dict_google.items():
    protocol = 'Both' if len(trans_protocol)==2 else list(trans_protocol)[0]
    device_pairs_list.append([device_pair[0], device_pair[1], protocol])
output_data('connectedGraph/test-google-cr.html', device_pairs_list, []) # 

device_pairs_list = []
for device_pair, trans_protocol in dict_apple.items():
    protocol = 'Both' if len(trans_protocol)==2 else list(trans_protocol)[0]
    device_pairs_list.append([device_pair[0], device_pair[1], protocol])
output_data('connectedGraph/test-apple-cr.html', device_pairs_list, []) # 