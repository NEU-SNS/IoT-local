import os
import networkx as nx
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
# import pygraphviz
# import pydot
# from networkx.drawing.nx_agraph import graphviz_layout
matplotlib.use('Agg')

# Define the paths to the two folders containing the TXT files
tcp_folder_path = '/home/hutr/local_output/idle-dataset-dec-new/tcp_output'
udp_folder_path = '/home/hutr/local_output/idle-dataset-dec-new/udp_output'
device_file = '/home/hutr/local-traffic-analysis/local-devices.txt'

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

single_node_list = []
for dev in device_list:
    if dev not in devices_has_traffic:
        single_node_list.append(dev)
# Create a set of unique device pairs and their corresponding protocol
device_pairs_list = []
for device_pair, trans_protocol in devices_dict.items():

    protocol = 'Both' if len(trans_protocol)==2 else list(trans_protocol)[0]

    device_pairs_list.append([device_pair[0], device_pair[1], protocol])


G = nx.Graph()
plt.figure(figsize=(12,12)) 
for item in device_pairs_list:
    # print(item)
    G.add_edge(item[0], item[1], transport=item[2]) # , highest=int(highest_protocol))
for dev in single_node_list:
    G.add_node(dev)


edge_styles = {'TCP': ':', 'UDP': '--', 'Both': '-'}
# color_map = ListedColormap(['#fee0d2', '#fc9272', '#de2d26'])  # Choose a color map for the highest protocol
# highest_levels = sorted(set(d['highest'] for u, v, d in G.edges(data=True)))
# edge_colors = {highest: color_map(i/(len(highest_levels)-1)) for i, highest in enumerate(highest_levels)}
# pos = nx.kamada_kawai_layout(G, weight=1.0, scale=1.0) #  
# pos = nx.nx_agraph.pygraphviz_layout(G, prog='neato')
pos = nx.spring_layout(G, k=1.0, scale=0.9, iterations=60, weight=1.0, seed=777)
# pos = nx.fruchterman_reingold_layout(G, k=0.5, scale=2, iterations=50, seed=555)

edge_colors = {'TCP': '#03fcfc', 'UDP': '#03fc94', 'Both': '#0380fc'}
for u, v, data in G.edges(data=True): 
    # if data['transport'] == 'TCP' and 'UDP' in G[u][v]['transport']:
    #     G[u][v]['transport'] = 'Both'
    style = '-' # edge_styles.get(data['transport'], '-')
    color = edge_colors.get(data['transport'], '#03a5fc')
    nx.draw_networkx_edges(G, pos, [(u, v)], style=style, width=2.5, edge_color=color,alpha=0.5) # edge_color='#03a5fc', 

# Define the node colors and draw the nodes and labels
# node_colors = ['red', 'blue', 'green', 'yellow', 'purple', 'orange', 'brown', 'pink', 'grey', 'cyan']

for i, node in enumerate(G.nodes()):
    color = '#CCE5FF' # node_colors[i % len(node_colors)]
    nx.draw_networkx_nodes(G, pos, [node], node_color=color, edgecolors='#03a5fc',node_size=180, alpha=0.8)
    nx.draw_networkx_labels(G, pos, {node: node}, font_size=8, font_color='black') # 



# Set the axis limits, remove the axis ticks and labels, and show the plot
plt.xlim(-1.2, 1.2)
plt.ylim(-1.2, 1.2)
plt.axis('off')
# sm = plt.cm.ScalarMappable(cmap=color_map, norm=plt.Normalize(vmin=min(highest_levels), vmax=max(highest_levels)))
# sm._A = []
# plt.colorbar(sm, label='Highest Protocol Level')
# plt.legend(handles=[plt.Line2D([], [], linestyle=style, color='black', linewidth=2.5) for style in edge_styles.values()],
#            labels=['TCP', 'UDP', 'Both'], loc='best')
dic = '/home/hutr/local-traffic-analysis/connectedGraph/test.pdf'
plt.savefig(dic)
