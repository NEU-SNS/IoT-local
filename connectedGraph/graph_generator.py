import math 
import os
import sys
import typing
from sklearn import preprocessing
import numpy as np 
import seaborn
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
matplotlib.use('Agg')
# import constants as c
min_max_scaler = preprocessing.MinMaxScaler((0,10))

def print_usage(is_error):
    # TODO
    print('visualization of local communication')
    return

"""
def output_data(out_file:str, dict_dec:dict[str, dict[str, int]]) -> bool: 
    # print('output:', out_file, dict_dec)
    # 
    with open(out_file, 'w') as of:
        # write nodes: 
        of.write('nodes = new vis.DataSet([')
        for i in range(len(dict_dec)):
            dev = list(dict_dec.keys())[i]
            of.write('{"id": "%s", "label": "%s", "shape": "dot", "size": 8}' % (dev,dev))
            if i != len(dict_dec)-1:
                of.write(', ')
            else:
                of.write(']);')
        of.write('\n\n')

        # write edges:
        of.write('edges = new vis.DataSet([')
        for i in range(len(dict_dec)):
            dev = list(dict_dec.keys())[i]
            dst_list = dict_dec[dev]
            if len(dst_list) == 0:
                continue
            
            for j in range(len(dst_list)): 
                dst_device = list(dst_list.keys())[j]
                dst_voulme = dst_list[dst_device]

                of.write('{"from": "%s", "to": "%s", "value": %f}' % (dev, dst_device, min_max_scaler.transform(np.array([float(dst_voulme)]).reshape(1, -1))))
                if i != len(dict_dec)-1 or j != len(dst_list)-1:
                    of.write(', ')
                else:
                    of.write(']);')
        

    return 0 
"""

def output_data(out_file: str, dict_dec, min_max_scaler) -> int:
    print('output:', out_file, dict_dec)
    # 
    with open(out_file, 'w') as of:

        # write header
        with open('connectedGraph/template-header.html') as hf:
            header = hf.read()
            of.write(header)

        # Add all top-level devices (with their own folder) to the node array
        nodes = []
        nodes.extend(dict_dec.keys())
        # Iterate through the top-level devices and add missing devices they talk to
        children = []
        for parent in nodes:
            for child in dict_dec[parent].keys():
                if child not in children and child not in nodes:
                    children.append(child)
        nodes.extend(children)
        # Generate the text list of nodes
        for i in range(len(nodes)):
            dev = nodes[i]
            of.write('        nodes.add([{id: "%s", label: "%s", shape: "dot", size: 8}]);\n' % (dev, dev))
        of.write('\n')

        # write edges:
        for i in range(len(dict_dec)):
            dev = list(dict_dec.keys())[i]
            dst_list = dict_dec[dev]
            if len(dst_list) == 0:
                continue

            for j in range(len(dst_list)):
                dst_device = list(dst_list.keys())[j]
                dst_volume = dst_list[dst_device]

                of.write('        edges.add([{from: "%s", to: "%s", width: %f}]);\n' % (
                    dev, dst_device, min_max_scaler.transform(np.array([float(dst_volume)]).reshape(1, -1))))
        of.write('\n')

        # write footer
        with open('connectedGraph/template-footer.html') as ff:
            footer = ff.read()
            of.write(footer)

    return 0

def heatmap(out_file: str, out_fig, dict_dec) -> int:
    # lower triangle heatmap
    """
    index: 
    
    """
    # tcp:
    if 'tcp' in out_file:
        index = ['amcrest-cam-wired',  'echodot',
        'echodot3a', 'echodot3b', 'echodot3c', 'echodot3d', 'echodot4a',
        'echodot4c', 'echodot5a', 'echodot5b', 'echoflex1', 'echoflex2',
        'echoplus', 'echoshow5', 'echoshow8', 'echospot', 't-echodot', 'chromecast-googletv',
        'google-home-mini', 'google-home-mini2', 'google-home-mini3',
        'google-nest-mini1', 'google-nest-mini2', 'nest-camera', 'nest-doorbell', 'nest-hub', 'nest-hub-max', 
            'tivostream', 'roku-tv', 
            'appletv-wifi', 'homepod', 'homepod-mini1',
        'homepod-mini2', 'lgtv-wired', 'meross-plug1', 'meross-plug2',
            't-philips-hub', 't-wemo-plug',
        'tplink-bulb', 'tplink-plug', 'firetv', 'fridge',]
    # udp:
    if 'udp' in out_file:
        index = ['amcrest-cam-wired',   'echodot',
        'echodot3a', 'echodot3b', 'echodot3c', 'echodot3d', 'echodot4a',
        'echodot4c', 'echodot5a', 'echodot5b', 'echoflex1', 'echoflex2', 'echoplus', 'echoshow5', 'echoshow8',
        'echospot', 't-echodot', 'chromecast-googletv', 'google-home-mini', 'google-home-mini2',
        'google-home-mini3', 'google-nest-mini1', 'google-nest-mini2',
        'nest-camera', 'nest-doorbell', 'nest-hub', 'nest-hub-max', 
        'tivostream','roku-tv', 'appletv-wifi',
        'homepod', 'homepod-mini1', 'homepod-mini2', 'lgtv-wired',
        'meross-plug1', 'meross-plug2',
        't-philips-hub', 't-wemo-plug',  'tplink-bulb',
        'tplink-plug',  'yeelight-bulb']
    data = pd.DataFrame.from_dict(dict_dec)
    # data = data.sort_values(data.columns[0])
    # data.sort_index(inplace=True)
    # data = data.reindex(sorted(data.columns), axis=1)
    print(data.columns)
    data = data.loc[index,index]
   
    
    
    # data.reindex(index)
    print(data)
    data.to_csv(out_file)
    plt.figure(figsize = (16,16))
    # matrix = np.triu(data)
    matrix = np.arange(data.shape[0])[:,None] <= np.arange(data.shape[1])
    seaborn.heatmap(data=data,square=True,linewidths=0.5, linecolor='gray', mask=matrix) # annot=True,
    
    plt.savefig(out_fig)
    
    return 0


def main():
    [ print_usage(0) for arg in sys.argv if arg in ("-h", "--help") ]

    print("Running %s..." % sys.argv[0])

    in_dir = sys.argv[1]
    out_dir = sys.argv[2]

    undirected_graph(in_dir, out_dir)
    # directed_graph(in_dir, out_dir)

def directed_graph(in_dir, out_dir):
    # ! Bug: not directed actually, need to generate different tcp_vis and udp_vis txt files. 
    dict_dec = {} # {device: {device: volume}}
    volume_standardization = []
    count = set()
    for dev_file in os.listdir(in_dir):
        if dev_file.startswith(".") or dev_file.startswith("log"):
            continue
        
        # output_file = os.path.join(out_dir, dev_dir + '.csv') # Output file
        if not dev_file.endswith(".txt"):
            continue
        
        device = dev_file.split('.')[0]
        # if device != 'amazon-plug':
        #     continue
        # if device not in dict_dec:
        dict_dec[device] = {}

    for dev_file in os.listdir(in_dir):
        if dev_file.startswith(".") or dev_file.startswith("log") or not dev_file.endswith(".txt"):
            continue
        
        device = dev_file.split('.')[0]
        
        dev_file_full =  os.path.join(in_dir, dev_file)
        with open(dev_file_full, 'r') as ff:
            lines = ff.readlines()
            for line in lines:
                if len(line) <= 1:
                    continue
                count.add(device)
                
                dst_device = line.strip().split(' ')[0]
                if dst_device not in dict_dec:
                    continue
                count.add(dst_device)
                dst_volume = int(line.strip().split(' ')[1])
                volume_standardization.append(dst_volume)
                if line.strip() == '':
                    continue
   
                if dst_device not in dict_dec[device]:
                    dict_dec[device][dst_device] = dst_volume
                else:
                    dict_dec[device][dst_device] += dst_volume
                    
    print('Count non-empty files:', len(count))
    print(count)

    volume_standardization = np.asarray(volume_standardization).reshape(-1, 1)
    min_max_scaler.fit(volume_standardization)
    new_dict_dev = {}
    for k in dict_dec:
        if k not in count:
            continue
        new_dict_dev[k] = {}
        for j in dict_dec[k]:
            if j not in count:
                continue
            # print(k, j)
            new_dict_dev[k][j] = min_max_scaler.transform(np.array(float(dict_dec[k][j])).reshape(1, -1))[0][0]
    
    if in_dir.endswith('/'):
        in_dir = in_dir[:-1]
    out_file = os.path.join(out_dir, os.path.basename(in_dir) + '_heatmap.csv')
    out_fig = os.path.join(out_dir, os.path.basename(in_dir) + '_heatmap.pdf')
    heatmap(out_file, out_fig, new_dict_dev) # 
    
    return 0 


def build_graph_dict(device, dst_device, dst_volume, dict_dec):
    if dst_device in dict_dec and device in dict_dec[dst_device]:
        dict_dec[dst_device][device] += dst_volume
    else:
        if dst_device not in dict_dec[device]:
            dict_dec[device][dst_device] = dst_volume
        else:
            dict_dec[device][dst_device] += dst_volume
    return dict_dec

def undirected_graph(in_dir, out_dir):
    dict_dec = {} # {device: {device: volume}}
    volume_standardization = []
    count = {}
    
    # Zoomed-in graphs: 
    dict_echo = {}
    dict_google = {}
    dict_apple = {}
    
    
    for dev_file in os.listdir(in_dir):
        if dev_file.startswith(".") or dev_file.startswith("log"):
            continue
        
        # output_file = os.path.join(out_dir, dev_dir + '.csv') # Output file
        if not dev_file.endswith(".txt"):
            # print(c.WRONG_EXT % ("input file", "txt", full_dec_file), file=sys.stderr)
            continue
        
        device = dev_file.split('.')[0]
        # if device != 'amazon-plug':
        #     continue
        if device not in dict_dec:
            dict_dec[device] = {}
            dict_echo[device] = {}
            dict_google[device] = {}
            dict_apple[device] = {}
        
        dev_file_full =  os.path.join(in_dir, dev_file)
        with open(dev_file_full, 'r') as ff:
            lines = ff.readlines()
            for line in lines:
                if len(line) <= 1:
                    continue
                
                
                dst_device = line.strip().split(' ')[0]
                if device not in count:
                    count[device] = set()
                count[device].add(dst_device)
                
                dst_volume = int(line.strip().split(' ')[1])
                volume_standardization.append(dst_volume)
                if line.strip() == '':
                    continue
                if 'echo' in dst_device or 'echo' in device:
                    dict_echo = build_graph_dict(device, dst_device, dst_volume, dict_echo)
                if 'google' in dst_device or 'google' in device or 'nest' in dst_device or 'nest' in device:
                    dict_google = build_graph_dict(device, dst_device, dst_volume, dict_google)
                if 'apple' in dst_device or 'apple' in device or 'homepod' in dst_device or 'homepod' in device:
                    dict_apple = build_graph_dict(device, dst_device, dst_volume, dict_apple)
                
                # undirected graph, which is not optimized 
                dict_dec = build_graph_dict(device, dst_device, dst_volume, dict_dec)
                # if dst_device in dict_dec and device in dict_dec[dst_device]:
                #     dict_dec[dst_device][device] += dst_volume
                # else:
                #     if dst_device not in dict_dec[device]:
                #         dict_dec[device][dst_device] = dst_volume
                #     else:
                #         dict_dec[device][dst_device] += dst_volume
    print('Count non-empty files:', len(count))
    
    ave = 0
    median = []
    for dev in count:
        ave += len(count[dev])
        median.append(len(count[dev]))
        print(dev, len(count[dev]))
    ave = ave/ 93 # len(count)
    # 93- len(median)
    padded_median = median + [0] * (93 - len(median))
    print('Average:', ave)
    print('Median:', np.median(padded_median))
    print('95th:', np.percentile(padded_median, 95))

    return 0 
    
    volume_standardization = np.asarray(volume_standardization).reshape(-1, 1)
    min_max_scaler.fit(volume_standardization)
    if in_dir.endswith('/'):
        in_dir = in_dir[:-1]
    out_file = os.path.join(out_dir, os.path.basename(in_dir) + '.html')
    output_data(out_file, dict_dec, min_max_scaler) # 

    new_dict_echo = {}
    for dev in dict_echo:
        if len(dict_echo[dev]) > 0:
            new_dict_echo[dev] = dict_echo[dev]
    output_data(os.path.join(out_dir, os.path.basename(in_dir) + 'echo' + '.html'), new_dict_echo, min_max_scaler)
    new_dict_google = {}
    for dev in dict_google:
        if len(dict_google[dev]) > 0:
            new_dict_google[dev] = dict_google[dev]
    output_data(os.path.join(out_dir, os.path.basename(in_dir) + 'google' + '.html'), new_dict_google, min_max_scaler)
    new_dict_apple = {}
    for dev in dict_apple:
        if len(dict_apple[dev]) > 0:
            new_dict_apple[dev] = dict_apple[dev]
    output_data(os.path.join(out_dir, os.path.basename(in_dir) + 'apple' + '.html'), new_dict_apple, min_max_scaler)
    # if in_dir.endswith('/'):
    #     in_dir = in_dir[:-1]
    # out_file = os.path.join(out_dir, os.path.basename(in_dir) + '_heatmap.csv')
    # out_fig = os.path.join(out_dir, os.path.basename(in_dir) + '_heatmap.pdf')
    # heatmap(out_file, out_fig, new_dict_dev) # 
    
    return 0 

if __name__ == "__main__":
    main()