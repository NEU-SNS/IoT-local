import sys
import os
import argparse
import numpy as np
import pickle
from multiprocessing import Process
from multiprocessing import Manager
from subprocess import Popen, PIPE
from collections import Counter
from copy import deepcopy
import csv
import matplotlib
import pyshark
import time
import pandas as pd
import threading
import json
from operator import add
from anytree import Node, RenderTree, NodeMixin

matplotlib.use('Agg')

from analyser.utils import *

class ProtocolTree(NodeMixin):  # Add Node feature
    
    
    def __init__(self, name, frame, byte, parent=None): # , add=False
        super(ProtocolTree, self).__init__()
        
        # if add:  # add mode
        #     self.frame = self.frame + frame
        #     self.byte = self.byte + byte
        # else:
        self.name = name
        self.frame = frame
        self.byte = byte
        self.parent = parent
        self.my_children = []
        
    def __str__(self):
        return "%s, %d, %d" % (self.name, self.frame, self.byte)
    
    def add_children(self, name):
        self.my_children.append(name)
    
    def has_children(self, name):
        if name in self.my_children:
            return True
        return False
    
    def path(self):
        my_path = []
        my_path.append(self.name)
        
        tmp_parent = self.parent
        while(tmp_parent != None):
            my_path.append(tmp_parent.name)
            tmp_parent = tmp_parent.parent
        
        my_path.reverse()
        return "/".join(my_path)
    
    def add(self, frame, byte):
        self.frame = self.frame + frame
        self.byte = self.byte + byte

def protocol_identify_tshark(model_dir, dict_dec):
    
    protocol_dict = {}
    for device in dict_dec:
        tmp_protocols = {}
        
        root_node = 0
        node_set = {}
        for pcap_file in dict_dec[device]:
            print(pcap_file)
            command = ["tshark", "-r", pcap_file, '-qz', 'io,phs']
            process = Popen(command, stdout=PIPE, stderr=PIPE)
            # Get output. Give warning message if any
            out, err = process.communicate()
            if err:
                print("Error reading file: '{}'".format(err.decode('utf-8')))
            
            
            
            layer_list = [0,0,0,0,0,0]
            
            for line in filter(None, out.decode('utf-8').split('\n')):
                # print(line)
                if not line.startswith("=") and not line.startswith("Protocol") and not line.startswith("Filter"):
                    
                    tmp_layer = int(line.split(':')[0][:-7].rstrip().count(" ")/2)
                    cur_protocol = line.split(':')[0][:-7].strip()
                    
                    
                    # print(cur_protocol, tmp_layer)
                    # print(line.split())
                    cur_frames = int(line.split()[1].split(':')[1])
                    cur_bytes = int(line.split()[2].split(':')[1])
                    tmp_protocols[tmp_layer] = tmp_protocols.get(tmp_layer, {})
                    
                    if cur_protocol not in tmp_protocols[tmp_layer]:
                        tmp_protocols[tmp_layer][cur_protocol] = [cur_frames, cur_bytes]
                    else:
                        # print(cur_protocol)
                        # print(tmp_protocols)
                        tmp_protocols[tmp_layer][cur_protocol] = list(map(add, tmp_protocols[tmp_layer][cur_protocol], [cur_frames, cur_bytes]))
                    
                    
                    if tmp_layer == 0:
                        if root_node == 0:
                            root_node = ProtocolTree(cur_protocol, cur_frames, cur_bytes)
                            # print(root_node.children)
                            layer_list[tmp_layer] = root_node
                            node_set[('root',cur_protocol)] = root_node
                        else:
                            root_node = node_set[('root',cur_protocol)]
                            layer_list[tmp_layer] = root_node
                            root_node.add(cur_frames, cur_bytes)
                            # print(root_node.my_children)
                    else:
                        # print(layer_list[tmp_layer-1])
                        if not layer_list[tmp_layer-1].has_children(cur_protocol):
                            tmp_node = ProtocolTree(cur_protocol, cur_frames, cur_bytes, parent=layer_list[tmp_layer-1])
                            # print(tmp_node.name, tmp_node.parent)
                            layer_list[tmp_layer-1].add_children(cur_protocol)
                            layer_list[tmp_layer] = tmp_node
                            # print(layer_list[tmp_layer-1].path())
                            node_set[(layer_list[tmp_layer-1].path(), cur_protocol)] = tmp_node
                            # node_set[(layer_list[tmp_layer-1].name,cur_protocol)] = tmp_node
                        else:
                            # print('add', layer_list[tmp_layer-1].path())
                            node_set[(layer_list[tmp_layer-1].path(), cur_protocol)].add(cur_frames, cur_bytes)
                            layer_list[tmp_layer] = node_set[(layer_list[tmp_layer-1].path(), cur_protocol)]
                            # node_set[(layer_list[tmp_layer-1].name,cur_protocol)].add(cur_frames, cur_bytes)
                            # layer_list[tmp_layer] = node_set[(layer_list[tmp_layer-1].name,cur_protocol)]
                        
                        
                    
                    
            # print(pcap_file, tmp_protocols)
        
        # print('----')
        # print('\nOverall:', tmp_protocols)
        # print('----')
        if not os.path.exists(model_dir):
            os.system('mkdir -pv %s' % model_dir)
        # print(root_node)
        # print(root_node.my_children)
        # print(node_set['ip'] .my_children)
        with open(os.path.join(model_dir, '%s.txt' % device), 'w') as f:
            f.write('Protocol                  Frame Byte\n')
            if len(node_set) == 0:
                continue
            for pre, fill, node in RenderTree(node_set[('root','eth')]):
                # print("%s%s" % (pre, node.name))
                treestr = u"%s%s" % (pre, node.name)
                # print(treestr.ljust(25), node.frame, node.byte)
                
                f.write('%s %s %s\n' % (treestr.ljust(25), node.frame, node.byte) )           

            f.write('\n\n')
            for k in tmp_protocols:
                f.write('Layer %s: %s\n' % (k, json.dumps(tmp_protocols[k])))
            # f.write(json.dumps(tmp_protocols))
        
                
def main():
    global mac_dic, out_dir
    [ print_usage(0) for arg in sys.argv if arg in ("-h", "--help") ]

    print("Running %s..." % sys.argv[0])

    # error checking
    # check for 2 or 3 arguments
    # if len(sys.argv) != 3 and len(sys.argv) != 4:
    #     print(c.WRONG_NUM_ARGS % (2, (len(sys.argv) - 1)))
    #     print_usage(1)
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("in_dir")
    parser.add_argument("out_dir")
    parser.add_argument("-f", dest="tshark_filter", default="")
    args = parser.parse_args()
    
    # in_dir = sys.argv[1]
    # out_dir = sys.argv[2]
    in_dir = args.in_dir
    out_dir = args.out_dir
    # str_num_proc = sys.argv[3] if len(sys.argv) == 4 else "5"

    cur_filter = args.tshark_filter
    
    # check in_dir
    errors = False
    if not os.path.isdir(in_dir):
        errors = True
        print(c.INVAL % ("Decoded pcap directory", in_dir, "directory"), file=sys.stderr)
    else:
        if not os.access(in_dir, os.R_OK):
            errors = True
            print(c.NO_PERM % ("decoded pcap directory", in_dir, "read"), file=sys.stderr)
        if not os.access(in_dir, os.X_OK):
            errors = True
            print(c.NO_PERM % ("decoded pcap directory", in_dir, "execute"), file=sys.stderr)
    if os.path.isdir(out_dir):
        if not os.access(out_dir, os.W_OK):
            errors = True
            print(c.NO_PERM % ("output directory", out_dir, "write"), file=sys.stderr)
        if not os.access(out_dir, os.X_OK):
            errors = True
            print(c.NO_PERM % ("output directory", out_dir, "execute"), file=sys.stderr)

    if errors:
        print_usage(1)
    # end error checking
    if not os.path.exists(out_dir):
        os.system('mkdir -pv %s' % out_dir)
    print("Input files located in: %s\nOutput files placed in: %s\n" % (in_dir, out_dir))


    mac_dic = read_mac_address()

    dict_dec = {}
    for dev_dir in os.listdir(in_dir):
        if dev_dir.startswith(".") or dev_dir.startswith("log"):
            continue
        
        # output_file = os.path.join(out_dir, dev_dir + '.csv') # Output file

        device = dev_dir
        if device[0] <= 'n':
            continue 
        # if device != 'amazon-plug': #  and device != 'google-home-mini':
        #     continue
        # if device != 'echodot3a': #  and device != 'google-home-mini':
        #     continue
        # if device != 't-philips-hub':
        #     continue
        # if device != 'google-home-mini':
        #     continue
        # if not device.startswith('echodot3'):
        #     continue
        if device not in dict_dec:
            dict_dec[device] = []
        full_dev_dir = os.path.join(in_dir, dev_dir)
        for dec_file in os.listdir(full_dev_dir):
            full_dec_file = os.path.join(full_dev_dir, dec_file)
            if not full_dec_file.endswith(".pcap"):
                print(c.WRONG_EXT % ("input file", "PCAP", full_dec_file), file=sys.stderr)
                continue
            if not os.access(full_dec_file, os.R_OK):
                print(c.NO_PERM % ("input file", full_dec_file, "read"), file=sys.stderr)
                continue
            dict_dec[device].append(full_dec_file)

    model_dir = os.path.join(out_dir, 'protocol_statistics')
    if not os.path.exists(model_dir):
        os.system('mkdir -pv %s' % model_dir)                

    protocol_identify_tshark(model_dir, dict_dec)
      
if __name__ == "__main__":
    
    # c = {'echodot':["/home/hutr/2022-datasets/idle-dataset/echodot/2022-08-23_18.52.25_192.168.10.226.pcap", 
    #                 "/home/hutr/2022-datasets/idle-dataset/echodot/2022-08-24_18.52.38_192.168.10.226.pcap",
    #                 "/home/hutr/2022-datasets/idle-dataset/echodot/2022-08-25_18.52.38_192.168.10.226.pcap",
    #                 "/home/hutr/2022-datasets/idle-dataset/echodot/2022-08-26_18.52.38_192.168.10.226.pcap",
    #                 "/home/hutr/2022-datasets/idle-dataset/echodot/2022-08-27_18.52.43_192.168.10.226.pcap",
    #                 "/home/hutr/2022-datasets/idle-dataset/echodot/2022-08-28_18.52.43_192.168.10.226.pcap"
    #                 ]}
    # d = {'amazon-plug':["/home/hutr/2022-datasets/idle-dataset/amazon-plug/2022-08-24_10.37.00_192.168.10.208.pcap"]}
    # protocol_identify_tshark('/home/hutr/local_output/idle-dataset/protocol_statistics',c)
    main()