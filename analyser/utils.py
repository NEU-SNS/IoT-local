import sys
import os
import argparse
import numpy as np
import pickle
import multiprocessing
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
import ipaddress
import json
import time
import analyser.constants as c
import datetime
import re
matplotlib.use('Agg')


MAC_ADDRESS_FILE = 'devices.txt'  # mac address file with ALL mac address to device name mappings. Not only devices, but phones
IP_ADDRESS_FILE = 'helper/ip_dict.txt'
DNS_ADDRESS = ['8.8.8.8', '8.8.4.4', '155.33.33.70', '155.33.33.75']
LOCAL_IPS = ['129.10.227.248', '129.10.227.207']
LOCAL_MACS = ['22:ef:03:1a:97:b9']


def output_file_generator(out_dir:str, basename:str, device:str) -> str:
    tmp_dir = os.path.join(out_dir, basename)
    if not os.path.exists(tmp_dir):
        os.system('mkdir -pv %s' % tmp_dir)
    output_file = os.path.join(tmp_dir, device + '.txt') # Output file
    return output_file

def addressing_method(address:str) -> str:
    """Determine traffic addressing method: unicast, multicast, broadcast

    Args:
        address (str): destination MAC address

    Returns:
        str: addressing method
    """

    if is_broadcast(address):
        return 2
    elif is_multicast(address):
        return 1
    # elif is_ipv6(address) and is_anycast(address):
    #     return 'anycast' 
    return 0

def is_broadcast(address:str) -> bool:
    return address=='ff:ff:ff:ff:ff:ff'


def is_multicast(address:str) -> bool:
    # if utils.validate_ip_address(address): 
    #     return ipaddress.ip_address("127.0.0.1").is_multicast
    return (address.startswith('01:00:5e') or address.startswith('33:33'))

def is_router(address1:str, address2:str) -> bool:
    return (address1 in LOCAL_MACS or address2 in LOCAL_MACS)


def is_local(ip_src, ip_dst):
    is_local = False
    try:
        is_local = (ipaddress.ip_address(ip_src).is_private and ipaddress.ip_address(ip_dst).is_private
                ) or (ipaddress.ip_address(ip_src).is_private and (ip_dst in LOCAL_IPS) 
                ) or (ipaddress.ip_address(ip_dst).is_private and (ip_src in LOCAL_IPS)) # =="129.10.227.248" or ip_dst=="129.10.227.207"
    except:
        # print('Error:', ip_src, ip_dst)
        return 1
    return is_local

def dig_x(ip):
    domain_name = ''
    # dig - x ip +short
    command = ["dig", "-x", ip, "+short"]
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output. Give warning message if any
    out, err = process.communicate()
    # print(out.decode('utf-8').split('\n'))
    return out.decode('utf-8').split('\n')[0]


def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        # print("IP address {} is valid. The object returned is {}".format(address, ip))
        return True
    except ValueError:
        # print("IP address {} is not valid".format(address)) 
        return False

def get_ip_type(address:str) -> None:
    try:
        ip = ipaddress.ip_address(address)

        if isinstance(ip, ipaddress.IPv4Address):
            print("{} is an IPv4 address".format(address))
        elif isinstance(ip, ipaddress.IPv6Address):
            print("{} is an IPv6 address".format(address))
    except ValueError:
        print("{} is an invalid IP address".format(address))

def is_ipv6(address:str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address):
            # print("{} is an IPv6 address".format(address))
            return True
        else:
            return False
    except ValueError:
        return False

def merge_pcap(new_pcap_dir, pcap_filter, pcap_list):
    print('merge pcap...')
    output_pcap = os.path.join(new_pcap_dir, pcap_filter+'.pcap')
    tmp_list = []
    # print(pcap_list)
    for i in pcap_list:
        tmp_list.append(os.path.join(new_pcap_dir, i))
    input_pcaps = ' '.join(tmp_list)

    os.system('mergecap -w %s %s' % (output_pcap, input_pcaps))
    for i in tmp_list:
        os.system('rm %s' % i)

    return 0

def read_device_ip():
    ip_file = IP_ADDRESS_FILE
    ip_dic = {}
    with open(ip_file, 'r') as f:
        data = f.read()
        ip_dic = json.loads(data)
        # lines = f.readlines()
        # for line in lines:
        #     if line.startswith(' ') or line.startswith('/n'):
        #         continue
        #     # print(line[:-1])
        #     tmp_ip, tmp_device = line[:-1].split(' ')
        #     if len(tmp_ip) != 14:
        #         print(tmp_ip, tmp_device)
        #         exit(1)

        #     ip_dic[tmp_device] = tmp_ip
    # print(ip_dic)
    return ip_dic



def read_mac_address():
    mac_file = MAC_ADDRESS_FILE
    mac_dic = {}
    with open(mac_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith(' ') or line.startswith('/n'):
                continue
            # print(line[:-1])
            tmp_mac, tmp_device = line[:-1].split(' ')
            if len(tmp_mac) != 17:
                mac_split = tmp_mac.split(':')
                for i in range(len(mac_split)):
                    if len(mac_split[i]) != 2:
                        mac_split[i]='0'+mac_split[i]
                tmp_mac = ':'.join(mac_split)
            mac_dic[tmp_device] = tmp_mac
    # print(mac_dic)
    return mac_dic

def calculate_metrics(TN, FP, FN, TP):

    # true positive + false positive == 0, precision is undefined; When true positive + false negative == 0

    if TP == 0 or TP + FP == 0 or TP + FN == 0:
        precision = 0
        recall = 0
        f1 = 0
    else:
        precision = TP / (TP + FP)
        recall = TP / (TP + FN)
        f1 = 2 * precision * recall / (precision + recall)
        # False positive rate
    FPR = FP / (FP + TN)
        # False negative rate
    FNR = FN / (TP + FN)

    return precision, recall, f1, FPR, FNR, TP, FP, FN


# def protocol_transform(test_protocols):
#     for i in range(len(test_protocols)):
#         if 'TCP' in test_protocols[i]:
#             test_protocols[i] = 'TCP'
#         elif 'MQTT' in test_protocols[i]:
#             test_protocols[i] = 'TCP'
#         elif 'UDP' in test_protocols[i]:
#             test_protocols[i] = 'UDP'
#         elif 'TLS' in test_protocols[i]:
#             test_protocols[i] = 'TCP'
#         if ';' in test_protocols[i]:
#             tmp = test_protocols[i].split(';')
#             test_protocols[i] = ' & '.join(tmp)
#     return test_protocols

