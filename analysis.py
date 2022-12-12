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

matplotlib.use('Agg')

from analyser.utils import *
from analyser.flow_extraction import extract_single, burst_split
import analyser.flow_extraction_new as flow_extraction_new
import analyser.plotting as plotting
from analyser.extract_ca import analyzePacket
from analyser.protocols_analysis import * 
from analyser.all_device_analysis import * 
from analyser.vis import *
# import nest_asyncio
# nest_asyncio.apply()

mac_dic = {}
inv_mac_dic = {}
out_dir = "~/local_output"

# TODO
def print_usage(is_error:bool) -> None:
    print(c.ANALYSIS_USAGE, file=sys.stderr) if is_error else print(c.ANALYSIS_USAGE)
    exit(is_error)



# TODO
# ! Bug, need to recreat all_packets_results instead of edit it 
def group_filter(dict_dec, all_packets_results, func, packet_index):
    for device in all_packets_results:
        cur_packets = all_packets_results[device]['packets']
        new_packets = []
        for packet in cur_packets:
            # print(packet[packet_index], func.__name__)
            if func(packet[packet_index]):
                new_packets.append(packet)
        all_packets_results[device]['packets'] = new_packets
    return all_packets_results

def BC_filter(dict_dec, all_packets_results):
    return group_filter(dict_dec, all_packets_results, is_broadcast, 5)

def MC_filter(dict_dec, all_packets_results):
    return group_filter(dict_dec, all_packets_results, is_multicast, 5)

def ipv6_filter(dict_dec, all_packets_results):
    return group_filter(dict_dec, all_packets_results, is_ipv6, 9)

def MC_analysis(model_dir, dict_dec, all_packets_results):
    for device in dict_dec:
        pass
    return 0 

def protocol_filter(dict_dec, all_packets_results, protocol):
    # filter a group of protocols 
    # TODO bugs
    # if protocol=='broadcast':
    #     return BC_filter(dict_dec, all_packets_results)
    # elif protocol=='multicast':
    #     return MC_filter(dict_dec, all_packets_results)
    # # elif protocol=='ipv6':
    # #     return ipv6_filter(dict_dec, all_packets_results)
    
    # protocol filter 
    protocol_lower = []
    for i in protocol:
        protocol_lower.append(i.lower())
    for device in dict_dec:
        if device not in all_packets_results:
            print('no device %s in protocol analysis' % device)
            # exit(1)
            continue
        cur_packets = all_packets_results[device]['packets']
        new_packets = []
        for packet in cur_packets:
            if packet[6].lower() not in protocol_lower:
                continue
            new_packets.append(packet)
        all_packets_results[device]['packets'] = new_packets

    return all_packets_results

def per_protocol_analysis(input_wrapper):
    out_dir, dict_dec, all_packets, pcap_filter = input_wrapper
    # tmp_com = 0
    # for i in range(len(list(all_packets.keys()))):
    #     if len(all_packets[list(all_packets.keys())[i]]) > 0:
    #         tmp_com = all_packets[list(all_packets.keys())[i]][0]
    #         break
    
    
    
    if isinstance(pcap_filter, list):
        return per_protocol_analysis_tshark(out_dir, dict_dec, all_packets, pcap_filter)
    else:
        print(pcap_filter)
        return per_protocol_analysis_pyshark(out_dir, dict_dec, all_packets, pcap_filter)

def per_protocol_analysis_pyshark(out_dir, dict_dec, all_packets_captures, pcap_filter):
    
    print('per_protocol_analysis_pyshark')
    # print(all_packets_captures)
    return protocols_analysis_pyshark(out_dir, dict_dec, all_packets_captures, pcap_filter)

def per_protocol_analysis_tshark(out_dir, dict_dec, all_packets_results, pcap_filter):
    print('per_protocol_analysis_tshark')
    # protocol = 'multicast'
    # mc_packets = protocol_filter(dict_dec, all_packets_results, protocol)

    # tcp_packets = protocol_filter(dict_dec, all_packets_results, protocol)
    
    new_packets = protocol_filter(dict_dec, all_packets_results, pcap_filter)
    return protocols_analysis_tshark(out_dir, dict_dec, new_packets, pcap_filter)



def idle_inputs(dict_dec:dict, model_dir:str, model_file_name:str, pcap_filter:str)->dict:
    """_summary_

    Args:
        dict_dec (dict): _description_
        model_dir (string): _description_
    Returns:
        dict: 
    """

    
    all_packets_results = {}
    # * process each device: 
    for device in dict_dec:

        packet_dir = os.path.join(model_dir, device)
        if not os.path.exists(packet_dir):
            os.system('mkdir -pv %s' % packet_dir)
        packets_file = packet_dir+'/%s.model' % model_file_name
        print(packets_file)
        if os.path.isfile(packets_file):
            print('reading')
            packets_results = pickle.load(open(packets_file, 'rb'))
        else:
            packets_results = {}
        if 'packets' in packets_results: #  and 'flows' in packets_results:
            all_packets_results[device] = packets_results
            # pickle.dump(packets_results, open(packets_file, 'wb'))
            continue
        else:
            # print(packets_results.keys())
            packets_original = {}
            packets_in_flows = {}
        # exit(1)
        # print(len(packets_original), len(packets_in_flows))
        # * extract features from PCAP files 
        
        results = []
        # results = {}
        print(device, dict_dec[device])
        for pcap_file in dict_dec[device]:
            tmp_res = extract_pcap_command_line(pcap_file, pcap_filter)
            if isinstance(tmp_res, int):
                continue
            # print(tmp_res.shape)
            # try:
            for tmp in tmp_res:
                results.append(tmp)
                # if len(tmp_res.shape) != 1:
                #     results = np.concatenate((results, tmp_res), axis=0) 
                # else: 
                #     results = np.concatenate((results, tmp_res.reshape(tmp_res.shape,1)), axis=0) 
            # except:
            #     print(device, 'failed!!!!! ', tmp_res.shape)
            #     print(tmp_res)
            #     continue

        if len(results) == 0 or len(results) == 1:
            print('Result==0')
            continue
        packets_original = results
        # print('Len packets_original:', len(packets_original))

        # TODO retransmisson
        try:
            flow_dic = extract_single(results)
            # print('len(flow_dic):', len(flow_dic))
            burst_threshold = 1
            burst_dic = burst_split(flow_dic, burst_threshold)
            if len(burst_dic) == 0:
                print('burst_dic==0')
                continue
            packets_in_flows = burst_dic
        except Exception as e:
            print(device, 'failed!!!!! ')
            print(str(e))
            continue

        # print('Len packets_in_flows:', len(packets_in_flows))
        packets_results = {'packets': packets_original, 'flows': packets_in_flows}
        all_packets_results[device] = packets_results
        # print('dumping')
        pickle.dump(packets_results, open(packets_file, 'wb'))

    return all_packets_results


def extract_pcap_command_line(pcap_file:str, pcap_filter:str) -> list[list[str]]:
    """extract features from a pcap file
    
    Args:
        pcap_file (_type_): PCAP file 

    Returns:
        list[list[str]]: list of packets
    """
    global mac_dic, inv_mac_dic
    dev_name = pcap_file.split('/')[-2]

    feature_header = ['number', 'time_epoch', 'time_delta', 'len (size)', 'src mac', 'dst mac', 'Protocol', 'layer 4 protocol code (optional)', 
                    'TCP/UDP stream (optional)', 'src ip (optional)', 'dst ip (optional)', 'src port (optional)', 'dst port (optional)']

    command = ["tshark", "-r", pcap_file, 
                "-Y", pcap_filter,
                "-Tfields",
                "-e", "frame.number",
                "-e", "frame.time_epoch",
                "-e", "frame.time_delta",
                "-e", "frame.len",
                "-e", "eth.src",
                "-e", "eth.dst",
                "-e", "_ws.col.Protocol",
                "-e", "ip.proto",   # layer 4 protocol id
                "-e", "ipv6.nxt",   # layer 4 protocol id
                "-e", "tcp.stream",
                "-e", "udp.stream",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.srcport",
                "-e", "udp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.dstport"
                ] # "-e", "_ws.expert"  tcp.analysis.flags
                # "-e", "ip.proto" # it returns transport layer protocol code. 
    result = []
    # Call Tshark on packets
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output. Give warning message if any
    out, err = process.communicate()
    if err:
        print("Error reading file: '{}'".format(err.decode('utf-8')))


    # Parsing packets
    my_device_mac =  mac_dic[dev_name]
    # print('Processing')
    
    for packet in filter(None, out.decode('utf-8').split('\n')):
        packet = np.array(packet.split())
        if packet[4] == 'ADwin' and packet[5] == 'Config':
            packet = np.delete(packet, 5)

        cur_time = packet[1]

        
        if my_device_mac == packet[5]:  # dst = my device, inbound traffic
            to_dev_mac = packet[4]

        else:   # extract destination for all outbound traffic
            to_dev_mac = packet[5]

        if to_dev_mac in inv_mac_dic: # known destination
            to_dev_name = inv_mac_dic[to_dev_mac]
        else:   # mutlicast/broadcast or unknown destination
            if addressing_method(to_dev_mac)==0 and not to_dev_mac.startswith('02:'):
                print('Unknown destination from %s:' % dev_name, to_dev_mac)
            to_dev_name = to_dev_mac
            # host = extract_host_new(ip_src, ip_dst, ip_host, count_dic, cur_time, whois_list)

        to_dev_name = to_dev_name.lower()
        packet = np.append(packet, to_dev_name) #append host as last column of output

        result.append(np.asarray(packet))
        # result = np.append(result, packet)
    result = np.asarray(result, dtype=object)

    if len(result) == 0:
        print('len(result) == 0')
        return 0

    return result



def pyshark_idle_input_threading(dict_dec:dict, out_dir:str, pcap_filter:str):
    num_thread = 12
    in_dev = [ [] for _ in range(num_thread) ]
    index = 0 
    for device in dict_dec:
        in_dev[index % num_thread].append(device)
        index += 1

    print('Mutlithreading... ', len(in_dev))
    threads = [None] * num_thread
    tmp_results = [None] * num_thread
    
    for i in range(len(threads)):
        tmp_dict_dev = {}
        for d in in_dev[i]:
            tmp_dict_dev[d] = dict_dec[d]
        if len(tmp_dict_dev.keys()) == 0:
            continue
        print('Thread %d:' % (i+1), tmp_dict_dev.keys())
        threads[i] = threading.Thread(target=pyshark_idle_input_threading_wrapper, args=(tmp_dict_dev, out_dir, pcap_filter, tmp_results, i))
        threads[i].start()

    for i in range(len(threads)):
        if threads[i] == None:
            continue
        threads[i].join()
    
    results = {}
    for i in range(len(tmp_results)):
        if threads[i] == None:
            continue
        if not isinstance(tmp_results[i], dict):
            print('thread result is not a dict')
            continue
        results = results | tmp_results[i] 
    print(len(results.keys()), results.keys())
    for k in results:
        print(k, len(results[k]))
    # exit(0)
    return results
    
def pyshark_idle_input_threading_wrapper(dict_dec:dict, out_dir:str, pcap_filter:str, tmp_result:dict, index:int):
    tmp_result[index] = pyshark_idle_input(dict_dec, out_dir, pcap_filter)
    return 0
    

def pyshark_idle_input(dict_dec:dict, out_dir:str, pcap_filter:str)->dict[str:list]:
    all_packets_captures = {}
    # * process each device: 

    # model_dir = os.path.join(out_dir, 'models')
    new_pcap_dir = os.path.join(out_dir, 'pcap')
    # t1 = time.time()
    for device in dict_dec:

        results = []
        # results = {}
        print(device)
        cur_new_pcap_dir = os.path.join(new_pcap_dir, device)
        if not os.path.exists(cur_new_pcap_dir):
            os.system('mkdir -pv %s' % cur_new_pcap_dir)
            
        # * All packet statistics
        if pcap_filter == "":
            all_packets_captures[device] = []
            for pcap_file in dict_dec[device]:
                tmp_capture = extract_pcap_pyshark(pcap_file, pcap_filter, '')
                # for tmp in tmp_capture:
                #     results.append(tmp)
                all_packets_captures[device].append(tmp_capture) 
                tmp_capture.close()
            continue

        # * if filtered file exists
        if os.path.isfile(os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap')):
            # pass
            # os.system('rm %s' % os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap'))
            # ! double check
            # print(, pcap_filter)
            results = extract_pcap_pyshark(os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap'), pcap_filter, '')
            # results2 = extract_pcap_pyshark(os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap'), pcap_filter, '')
            # print(results[0])
            all_packets_captures[device] = results
            
            print('reading... Protocol %s, Device %s' % (pcap_filter, device), len(results), isinstance(results, pyshark.FileCapture))


            results.close()

            continue
        
        # * filter each file 
        tmp_count = 0 
        for pcap_file in dict_dec[device]:
            tmp_count += 1
            tmp_capture = extract_pcap_pyshark(pcap_file, pcap_filter, os.path.join(cur_new_pcap_dir, pcap_filter+str(tmp_count)+'.pcap'))

            # if isinstance(tmp_capture, int):
            #     continue
            # # print(len(tmp_capture))
            # try:
            # for tmp in tmp_capture:
            #     results.append(tmp)
            # tmp_capture.close()
            # except:
            #     print(device, 'failed!!!!! ', tmp_capture)
            #     tmp_capture.close()
            #     # print(tmp_capture)
            #     continue

        merge_list = []
        for tmp_pcap in os.listdir(cur_new_pcap_dir):
            if not tmp_pcap.endswith('.pcap') or pcap_filter == "":
                continue
            if tmp_pcap.startswith(pcap_filter):
                merge_list.append(tmp_pcap)

        if len(merge_list) != 0:
            merge_pcap(cur_new_pcap_dir, pcap_filter, merge_list)
        
        if os.path.isfile(os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap')):
            results = extract_pcap_pyshark(os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap'), pcap_filter, '')
            all_packets_captures[device] = results
            results.close()
            print('Protocol %s, Device %s: %d packets' % (pcap_filter, device, len(results)))
            continue

        if len(results) == 0 or len(results) == 1:
            print('%s Result==0' % device)
            continue
        print('Protocol %s, Device %s: %d packets' % (pcap_filter, device, len(results)))
        # print(results[0])
        # exit(1)
        # remove ? 
        all_packets_captures[device] = results

    # print('Time1:', time.time()-t1)
    return all_packets_captures


def extract_pcap_pyshark(pcap_file:str, pcap_filter:str, output_pcap):
    capture = 0
    if pcap_filter=='multicast':
        pcap_filter='eth.addr!=ff:ff:ff:ff:ff:ff&&eth.dst.ig==1'
    if output_pcap == '':
        print(pcap_file, pcap_filter)
        
        capture = pyshark.FileCapture(str(pcap_file), display_filter=pcap_filter) # 
        
        return capture

    # print(pcap_file, pcap_filter, output_pcap)
    # capture = pyshark.FileCapture(str(pcap_file), display_filter=pcap_filter, output_file=str(output_pcap)) 

    # tshark is faster than pyshark in saving filtered traffic into a new pcap file
    os.system('tshark -r %s -Y %s -w %s' % (str(pcap_file), pcap_filter, str(output_pcap)))
    return 0
    


def main():
    global mac_dic, out_dir, inv_mac_dic
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
    inv_mac_dic = {v: k for k, v in mac_dic.items()}
    dict_dec = {}
    for dev_dir in os.listdir(in_dir):
        if dev_dir.startswith(".") or dev_dir.startswith("log"):
            continue
        
        # output_file = os.path.join(out_dir, dev_dir + '.csv') # Output file

        device = dev_dir
        # if device != 'amazon-plug' and device != 'google-home-mini':
        #     continue
        # if device != 'echodot': #  and device != 'google-home-mini':
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

    model_dir = os.path.join(out_dir, 'models')
    if not os.path.exists(model_dir):
        os.system('mkdir -pv %s' % model_dir)

    """
    input and output
    """

    # # * all packets 
    # pcap_filter = "not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission and not tcp.analysis.lost_segment"
    # # pcap_filter = "not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission"
    # pcap_filter = 'frame.time>="2022-08-25 12:00:00" and frame.time<="2022-08-29 11:59:59"'
    pcap_filter = ""
    # all_packets_results = idle_inputs(dict_dec, model_dir, 'packets', pcap_filter)
    
    # # # # basic output: charts
    # basic_analysis_output(model_dir, out_dir,  dict_dec, all_packets_results)
    
    # # protocol analysis 
    # tshark_protocol_filter = ['ssl', 'tlsv1','AJP13', 'VITA', 'ESO', 'RRoCE', 'BAT_GW', 'BFD', 'AX4000', 'BAT_VIS', 'DHCPv6', 'CoAP']
    # multiprocessing_wrapper(out_dir, dict_dec, all_packets_results, tshark_protocol_filter)
    
    # * unicast ethenet traffic only
    # pcap_filter = "!ip and eth.dst.ig==0"
    # unicast_nonip_results = idle_inputs(dict_dec, model_dir, 'unicast_nonip', pcap_filter)
    # basic_analysis_output(model_dir, os.path.join(out_dir,'eth_unicast'),  dict_dec, unicast_nonip_results)

    # * broadcast and multicast traffic 
    # pcap_filter = "eth.dst.ig==1"
    # all_packets_results = idle_inputs(dict_dec, model_dir, 'bcmc', pcap_filter)
    # basic_analysis_output(model_dir, os.path.join(out_dir,'bcmc'),  dict_dec, all_packets_results)

    # bc_packets_results = protocol_filter(dict_dec, all_packets_results, 'broadcast')
    # basic_analysis_output(model_dir, os.path.join(out_dir,'bc'),  dict_dec, bc_packets_results)

    # mc_packets_results = protocol_filter(dict_dec, all_packets_results, 'multicast')
    # basic_analysis_output(model_dir, os.path.join(out_dir,'mc'),  dict_dec, mc_packets_results)

    
    # cur_filter = 'dhcp'
    if cur_filter != "":
        """
        protocol specific analysis
        """
        print('Current Filter: ', cur_filter)
        # exit(1)
        all_packets_captures = pyshark_idle_input_threading(dict_dec, out_dir, cur_filter)
        multiprocessing_wrapper(out_dir, dict_dec, all_packets_captures, cur_filter)
    else:
        """
        Protocol statistics
        """
        # exit(0)
        
        print('Protocol statistics')
        # return 0
        cur_filter = ""
        all_packets_captures = pyshark_idle_input_threading(dict_dec, out_dir, cur_filter)
        multiprocessing_protocol_identification(out_dir, dict_dec, all_packets_captures)
    

def multiprocessing_wrapper(out_dir, dict_dec, all_packets_captures, cur_filter):
    """The mutliprocessing wrapper for per protocol analysis 

    Args:
        out_dir (_type_): output dir 
        dict_dec (_type_): dictionary of devices.
        all_packets_captures (_type_): dictionary of packets for each device 
        cur_filter (_type_): tshark filter
    """
    num_proc = 20
    in_dev = [ [] for _ in range(num_proc) ]
    index = 0 
    for device in dict_dec:
        in_dev[index % num_proc].append(device)
        index += 1

    print('Mutliprocessing... ', len(in_dev))
    procs = []
    manager = Manager()
    return_dict = manager.dict()
    for i in range(len(in_dev)):
        device_list = in_dev[i]
        if len(device_list)==0:
            continue
        new_packets_captures = {}
        for device in device_list:
            if device not in all_packets_captures:
                continue
            new_packets_captures[device] = all_packets_captures[device]
        input_wrapper = [out_dir, device_list, new_packets_captures, cur_filter]
        p = Process(target=run_protocol_analysis, args=(input_wrapper, i ,return_dict))
        procs.append(p)
        p.start()

    for p in procs:
        p.join()
    
    # skip tshark command line input 
    if isinstance(cur_filter, list):
        return 0
    protocols_out_file = os.path.join(out_dir, 'protocols', '%s.csv' % cur_filter)
    tmp_results = []
    header = []
    for k, v in return_dict.items():
        print(k,v)
        if not isinstance(v, tuple) or v[1] == 0:
            continue
        header = v[0]
        for row in v[1]:
            tmp_results.append(row)
    overall_result = [0 for _ in range(len(header))]
    for i in range(len(overall_result)):
        if i == 0:
            overall_result[0] = 'Overall'
            continue
        tmp_sum = 0
        for j in range(len(tmp_results)):
            tmp_sum += tmp_results[j][i]
        overall_result[i] = tmp_sum
    
    
    with open(protocols_out_file, 'w') as f:
        write = csv.writer(f)
        write.writerow(header)
        write.writerows(tmp_results)
        write.writerow(overall_result)


def run_protocol_analysis(input_wrapper, procnum, return_dict):
    """ Run per_protocol_analysis

    Args:
        input_wrapper (_type_): input params
        procnum (_type_): process number 
        return_dict (_type_): multiprocessing safe output dictionary
    """
    return_dict[procnum] = per_protocol_analysis(input_wrapper)

def multiprocessing_protocol_identification(out_dir, dict_dec, all_packets_captures):
    """The mutliprocessing wrapper for per protocol identification 

    Args:
        out_dir (_type_): output dir 
        dict_dec (_type_): dictionary of devices.
        all_packets_captures (_type_): dictionary of packets for each device 
    """
    num_proc = 20
    in_dev = [ [] for _ in range(num_proc) ]
    index = 0 
    for device in dict_dec:
        in_dev[index % num_proc].append(device)
        index += 1

    print('Mutliprocessing... ', len(in_dev))
    procs = []
    manager = Manager()
    return_dict = manager.dict()
    for i in range(len(in_dev)):
        device_list = in_dev[i]
        if len(device_list)==0:
            continue
        new_packets_captures = {}
        for device in device_list:
            if device not in all_packets_captures:
                continue
            new_packets_captures[device] = all_packets_captures[device]

        p = Process(target=protocol_identification_wrapper, args=(device_list, new_packets_captures, i ,return_dict, out_dir))
        procs.append(p)
        p.start()

    for p in procs:
        p.join()
    
    return 0

    protocols_out_dir = os.path.join(out_dir, 'protocol_statistics_pyshark')
    if not os.path.exists(protocols_out_dir):
        os.system('mkdir -pv %s' % protocols_out_dir) 
        
    
    protocol_dict = {}
    addressing_method_list = {}
    for k, v in return_dict.items():
        # print(k,v)
        protocol_dict = protocol_dict | v[0]
        addressing_method_list = addressing_method_list | v[1]

    count_all = {}
    count_ip = {}
    count_v6 = {}
    count_tcp = {}
    count_udp = {}
    count_tls = {}
    protocol_set = set()
    protocol_set.add('eth')
    for dev in protocol_dict:
        count_all[dev] = protocol_dict[dev]['2'].get('eth', 0)
        count_ip[dev] = 0
        count_v6[dev] = 0
        count_tcp[dev] = 0
        count_udp[dev] = 0
        count_tls[dev] = 0
        layer3_protocol = protocol_dict[dev]['3']
        layer4_protocol = protocol_dict[dev]['4']
        layer5_protocol = protocol_dict[dev]['5']
        # count IP and Non IP
        for cur_protocol in layer3_protocol:
            protocol_set.add(cur_protocol)
            if cur_protocol == 'ip' or cur_protocol == 'ipv6':
                count_ip[dev] += layer3_protocol[cur_protocol]
                # IPv4 and IPv6
                if cur_protocol == 'ipv6':
                    count_v6[dev] += layer3_protocol[cur_protocol]

        # UDP and TCP
        for cur_protocol in layer4_protocol:
            protocol_set.add(cur_protocol)
            if cur_protocol == 'tcp':
                count_tcp[dev] += layer4_protocol[cur_protocol]
            elif cur_protocol == 'udp':
                count_udp[dev] += layer4_protocol[cur_protocol]

        # tls
        for cur_protocol in layer5_protocol:
            protocol_set.add(cur_protocol)
            if cur_protocol == 'tls' or cur_protocol == 'ssl':
                count_tls[dev] += layer5_protocol[cur_protocol]

    protocol_device_count = {}
    for i in protocol_set:
        protocol_device_count[i] = set()
        
    for dev in protocol_dict:
        with open(os.path.join(protocols_out_dir, '%s.txt' % dev), 'w') as f:
            f.write('Overall: %d\n' % count_all[dev])
            f.write('IP: %d\n' % count_ip[dev])
            f.write('IPv6: %d\n' % count_v6[dev])
            f.write('TCP: %d\n' % count_tcp[dev])
            f.write('UDP: %d\n' % count_udp[dev])
            f.write('TLS: %d\n' % count_tls[dev])
            
            for k in protocol_dict[dev]:
                f.write('Layer %s: %s\n' % (k, json.dumps(protocol_dict[dev][k]))) 
                for j in protocol_dict[dev][k]:
                    protocol_device_count[j].add(dev)
            f.write('\n')
            f.write('Unicast: %d\n' % addressing_method_list[dev][0])
            f.write('Multicast: %d\n' % addressing_method_list[dev][1])
            f.write('Broadcast: %d\n' % addressing_method_list[dev][2])
    
    with open(os.path.join(protocols_out_dir, '_overall.txt'), 'w') as f:

            
        sorted_protocol_device_count = sorted([(k,len(v)) for k,v in protocol_device_count.items()], key=lambda t:t[1], reverse=True)
        for i in sorted_protocol_device_count:
            # if i[0] == 'eth':
            #     continue
            f.write('%s: %d | %s\n\n' % (i[0], i[1], ', '.join(list(protocol_device_count[i[0]]))))
            

def protocol_identification_wrapper(dict_dec, all_packets_captures, procnum, return_dict, out_dir):
    return_dict[procnum] = protocol_identification(dict_dec, all_packets_captures, out_dir)

def protocol_identification(dict_dec, all_packets_captures, out_dir):
    """_summary_

    Args:
        out_dir (_type_): output dir
        dict_dec (_type_): dict of devices with input files 
        all_packets_captures (_type_): pyshark capture objects 
    """
    global mac_dic, inv_mac_dic
    protocol_dict = {}
    addressing_method_list = {}
    for device in dict_dec:
        tmp_protocols = {'2':{}, '3':{}, '4':{}, '5':{}}
        tmp_addressing_method_list = [0,0,0]
        # for f in dict_dec[device]:

        cur_packets_set = all_packets_captures[device]
        tmp_count = 0
        periodic_detection_packets = []## packet.frame_info.time_delta
        my_device_mac =  mac_dic[device]
        
        t1 = time.time()
        for cur_packets in cur_packets_set:
            for packet in cur_packets:
                tmp_count += 1
                if tmp_count%10000 == 0:
                    print(tmp_count, time.time()-t1)
                is_UDP = False
                cur_layers = []
                sport = '0'
                dport = '0'
                for i in packet.layers:
                    cur_layers.append(i.layer_name)

                # unicast multicast broadcast:
                tmp_addressing_method_list[addressing_method(packet.eth.dst)] += 1
                
                # layer 2 eth: all packet count 
                # print(tmp_protocols)
                tmp_protocols['2'][cur_layers[0]] = tmp_protocols['2'].get(cur_layers[0], 0) + 1
                
                # layer 3: IP or Non IP, v4 and v6
                tmp_protocols['3'][cur_layers[1]] = tmp_protocols['3'].get(cur_layers[1], 0) + 1
                highest_protocol = cur_layers[1]
                # layer 4: TCP UDP (or other layer 3 protocols built upon IP)
                if len(cur_layers) > 2:
                    tmp_protocols['4'][cur_layers[2]] = tmp_protocols['4'].get(cur_layers[2], 0) + 1
                    if cur_layers[2] == 'udp':
                        is_UDP = True
                        sport = packet.udp.srcport
                        dport = packet.udp.dstport
                    elif cur_layers[2] == 'tcp':
                        sport = packet.tcp.srcport
                        dport = packet.tcp.dstport
                    highest_protocol = cur_layers[2]
                    
                # layer 5
                if len(cur_layers) > 3 and cur_layers[2] != 'icmp' and cur_layers[3] != 'data' and cur_layers[3] != 'ajp13':
                    tmp_layer_name = cur_layers[3]
                    if tmp_layer_name == 'tcp.segments' and len(cur_layers) > 4:
                        tmp_layer_name = cur_layers[4]
                        
                    if is_UDP and tmp_layer_name not in ['dns','mdns', 'dhcp', 'ssdp', 'classicstun', 'tplink-smarthome'] and len(packet.udp.payload) > 350:
                        # print(tmp_layer_name)
                        if check_upnp(packet.udp.payload): 
                            # is UPnP/SSDP
                            tmp_layer_name = 'ssdp'
                    
                    tmp_protocols['5'][tmp_layer_name] = tmp_protocols['5'].get(tmp_layer_name, 0) + 1
                    highest_protocol = tmp_layer_name
                # print(tmp_protocols)
                
                # if is_UDP and cur_layers.index('udp') != len(cur_layers)-1 and \
                    # cur_layers[cur_layers.index('udp')+1] not in ['dns','mdns','data', 'dhcp', 'ssdp', 'classicstun', 'tplink-smarthome']:
                src_mac = packet.eth.src
                dst_mac = packet.eth.dst
                if dst_mac == my_device_mac:
                    tmp_mac = src_mac
                    src_mac = dst_mac
                    dst_mac = tmp_mac
                    tmp_port = sport
                    sport = dport
                    dport = tmp_port
                
                if dst_mac in inv_mac_dic:
                    dst_dev = inv_mac_dic[dst_mac]
                else:
                    dst_dev = dst_mac
                periodic_detection_packets.append([packet.sniff_timestamp, packet.frame_info.time_delta, highest_protocol, dst_dev, sport, dport])
                
        
        flows = flow_extraction_new.extract_single(periodic_detection_packets)
        bursts = flow_extraction_new.burst_split(flows)
        print(tmp_count, time.time()-t1)
        
        
        
        header = ['time_epoch', 'time_delta', 'protocol', 'dst', 'sport', 'dport'] 
        flow_extraction_new.flows_output(bursts, out_dir, device)
        
        protocol_dict[device] = tmp_protocols
        addressing_method_list[device] = tmp_addressing_method_list
    return [protocol_dict, addressing_method_list]
        
def check_upnp(udp_payload):
    udp_payload = ''.join(udp_payload.split(':'))
    # print(udp_payload)
    try:
        decoded_payload = bytes.fromhex(udp_payload).decode('utf-8')
        # print(decoded_payload)
    except:
        return False
    if 'ssdp' in decoded_payload.lower() or 'upnp' in decoded_payload.lower():
        return True
    return False



if __name__ == "__main__":
    main()
    # return 0 
    