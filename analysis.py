from analyser.utils import *
# from analyser.flow_extraction import extract_single, burst_split
# import analyser.plotting as plotting
from analyser.protocols_analysis import * 
from analyser.all_device_analysis import * 
from analyser.vis import *
from analyser.protocol_identification import * 


# import nest_asyncio
# nest_asyncio.apply()

mac_dic = {}
inv_mac_dic = {}
out_dir = "~/local_output"

# TODO
def print_usage(is_error:bool) -> None:
    print(c.ANALYSIS_USAGE, file=sys.stderr) if is_error else print(c.ANALYSIS_USAGE)
    exit(is_error)



def pyshark_idle_input_threading(dict_dec:dict, out_dir:str, pcap_filter:str):
    num_thread = 12
    in_dev = [ [] for _ in range(num_thread) ]
    index = 0 
    for device in dict_dec:
        in_dev[index % num_thread].append(device)
        index += 1

    print('Multithreading... ', len(in_dev))
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
    # for k in results:
    #     print(k, len(results[k]))
    # # exit(0)
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
            # cur_packets = []
            all_packets_captures[device] = []
            # capture_file = os.path.join(new_pcap_dir, device, 'all.capture')
            # if os.path.isfile(capture_file):
            #     continue
            for pcap_file in dict_dec[device]:
                tmp_capture = extract_pcap_pyshark(pcap_file, pcap_filter, '')
                # for tmp in tmp_capture:
                #     results.append(tmp)
                all_packets_captures[device].append(tmp_capture) 
                tmp_capture.close()
            
            # pickle.dump(cur_packets, open(capture_file, 'wb'))
            
            continue

        # * if protocol-filtered file exists, load the pcap
        if os.path.isfile(os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap')):
            # pass
            # os.system('rm %s' % os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap'))
            # ! double check
            # print(, pcap_filter)
            results = extract_pcap_pyshark(os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap'), pcap_filter, '')
            # results2 = extract_pcap_pyshark(os.path.join(cur_new_pcap_dir, pcap_filter+'.pcap'), pcap_filter, '')
            # print(results[0])
            
            # returned a pyshark object
            all_packets_captures[device] = results
            
            print('Loading... Protocol %s, Device %s' % (pcap_filter, device), len(results), isinstance(results, pyshark.FileCapture))

            results.close()

            continue
        
        # * filter each pcap files in the dataset. 
        tmp_count = 0 
        for pcap_file in dict_dec[device]:
            tmp_count += 1
            # filter by protocol and save into new pcap files. 
            extract_pcap_pyshark(pcap_file, pcap_filter, os.path.join(cur_new_pcap_dir, pcap_filter+str(tmp_count)+'.pcap'))

        # * merging pcap files to make it more organized 
        merge_list = []
        for tmp_pcap in os.listdir(cur_new_pcap_dir):
            if not tmp_pcap.endswith('.pcap') or pcap_filter == "":
                continue
            if tmp_pcap.startswith(pcap_filter):
                merge_list.append(tmp_pcap)
        if len(merge_list) != 0:
            merge_pcap(cur_new_pcap_dir, pcap_filter, merge_list)
        
        # * load the merged file and save it in the packets_cpatures 
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
    # TODO Change the func name. It's not using pyshark, it's called protocol fileter
    capture = 0
    if pcap_filter=='multicast':
        pcap_filter="eth.addr!=ff:ff:ff:ff:ff:ff&&eth.dst.ig==1"
    elif pcap_filter=='broadcast':
        pcap_filter="eth.addr==ff:ff:ff:ff:ff:ff&&eth.dst.ig==1"
    elif output_pcap == '':
        # protocol-filtered file alread existed
        # print('Loading: ', pcap_file, pcap_filter)
        
        capture = pyshark.FileCapture(str(pcap_file), display_filter=pcap_filter) # 
        
        return capture

    # print(pcap_file, pcap_filter, output_pcap)
    # print('tshark -r %s -Y "%s" -w %s' % (str(pcap_file), pcap_filter, str(output_pcap)))
    # capture = pyshark.FileCapture(str(pcap_file), display_filter=pcap_filter, output_file=str(output_pcap)) 
    # exit(1)
    
    # tshark is faster than pyshark in saving filtered traffic into a new pcap file
    os.system('tshark -r %s -Y "%s" -w %s' % (str(pcap_file), pcap_filter, str(output_pcap)))
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
    parser.add_argument("-f", "--tsharkfilter", dest="tshark_filter", default="")
    parser.add_argument("-b", "--basic",dest="basic_analysis", action='store_const', default=False, const=True)
    parser.add_argument("-a", "--addressing", dest="addressing", default="")
    args = parser.parse_args()

    in_dir = args.in_dir
    out_dir = args.out_dir
    # str_num_proc = sys.argv[3] if len(sys.argv) == 4 else "5"

    cur_filter = args.tshark_filter
    basic_analysis_flag = args.basic_analysis
    addressing_method_filter = args.addressing
    
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
        # if device != 'yeelight-bulb': # and device != 'ikea-hub' :  # and device != 'google-home-mini'
        #     continue
        # if not device.startswith('echodot3a'):
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

    

    """
    input and output
    """

    # # * all packets 
    # pcap_filter = "not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission and not tcp.analysis.lost_segment"
    # # pcap_filter = "not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission"
    # pcap_filter = 'frame.time>="2022-08-25 12:00:00" and frame.time<="2022-08-29 11:59:59"'
    pcap_filter = ""
    tmp_models_name = 'packets'
    
    if addressing_method_filter!= "":
        # * unicast ethenet traffic only
        if addressing_method_filter == "eth_unicast":
            pcap_filter = "!ip and !ipv6 and eth.dst.ig==0"
            out_dir = os.path.join(out_dir,'eth_unicast')
            tmp_models_name = 'unicast_nonip'
        
        # * broadcast and multicast traffic 
        elif addressing_method_filter == "bcmc":
            pcap_filter = "eth.dst.ig==1"
            out_dir = os.path.join(out_dir,'bcmc')
            tmp_models_name = 'bcmc'
        
        # * unicast traffic 
        elif addressing_method_filter == 'unicast':
            pcap_filter = "eth.dst.ig==0"
            out_dir = os.path.join(out_dir,'unicast')
            tmp_models_name = 'unicast'
        
        elif addressing_method_filter == 'ipv6':
            pcap_filter = "ipv6"
            out_dir = os.path.join(out_dir,'ipv6-only')
            tmp_models_name = 'ipv6-only'

        if not os.path.exists(out_dir):
            os.system('mkdir -pv %s' % out_dir)
    
    if basic_analysis_flag:
        # ! to be removed. All functions of this part have been replaced by the protocl_identification module
        print('Start basic analysis.......')
        # all_packets_results = 
        model_dir = os.path.join(out_dir, 'models')
        if not os.path.exists(model_dir):
            os.system('mkdir -pv %s' % model_dir)
        idle_inputs(dict_dec, model_dir, tmp_models_name, pcap_filter)
        
        
        
        # basic output: charts ｜ function in all_device_analysis.py
        basic_analysis_output(model_dir, out_dir,  dict_dec, tmp_models_name)
    
    


    if cur_filter != "": #  or addressing_method_filter != ""
        """ 
        protocol specific analysis
        """
        print('Current Filter: ', cur_filter)
        # exit(1)
        all_packets_captures = pyshark_idle_input_threading(dict_dec, out_dir, cur_filter)
        multiprocessing_protocol_wise_analysis(out_dir, dict_dec, all_packets_captures, cur_filter)
    else:
        """
        Protocol statistics
        """
        # exit(0)
        
        print('Protocol statistics')
        # cur_filter = "ipv6"
        # cur_filter = ""
        if pcap_filter != "":
            cur_filter = pcap_filter
        all_packets_captures = pyshark_idle_input_threading(dict_dec, out_dir, cur_filter)
        # * multiprocessing_protocol_identification from analser.protocol_identification module
        multiprocessing_protocol_identification(out_dir, dict_dec, all_packets_captures)
        
        # # * uncomment to skip pcap reading and processing part, outputing only: 
        # return_dict_output = os.path.join(out_dir, 'protocol_statistics_pyshark') + '/_return_dict.model' 
        # return_dict = pickle.load(open(return_dict_output, 'rb'))
        # protocol_identification_outputing(out_dir, os.path.join(out_dir, 'protocol_statistics_pyshark'), return_dict)
    

def multiprocessing_protocol_wise_analysis(out_dir, dict_dec, all_packets_captures, cur_filter):
    """The mutliprocessing wrapper for per protocol analysis 

    Args:
        out_dir (_type_): output dir 
        dict_dec (_type_): dictionary of devices.
        all_packets_captures (_type_): dictionary of packets for each device 
        cur_filter (_type_): tshark filter
    """
    try:
        cpu_count = int(multiprocessing.cpu_count())
        num_proc = cpu_count-2
    except:
        num_proc = 30
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
    
    if os.path.exists(os.path.join(out_dir, 'protocols')):
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
    # call per_protocol_analysis
    return_dict[procnum] = per_protocol_analysis(input_wrapper)


def per_protocol_analysis(input_wrapper):
    """ determine which analysis should it run: tshark or pyshark

    Args:
        input_wrapper (_type_): _description_

    Returns:
        _type_: _description_
    """
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
    """call protocols_analysis_pyshark in analyzer.protocols_analysis module

    Args:
        out_dir (_type_): _description_
        dict_dec (_type_): _description_
        all_packets_captures (_type_): _description_
        pcap_filter (_type_): _description_

    Returns:
        _type_: _description_
    """
    print('per_protocol_analysis_pyshark')
    # print(all_packets_captures)
    return protocols_analysis_pyshark(out_dir, dict_dec, all_packets_captures, pcap_filter)

def per_protocol_analysis_tshark(out_dir, dict_dec, all_packets_results, pcap_filter):
    """call per_protocol_analysis_tshark in analyzer.protocols_analysis module
    # TODO This one is rarely used. Should consider remove it 

    Args:
        out_dir (_type_): _description_
        dict_dec (_type_): _description_
        all_packets_results (_type_): _description_
        pcap_filter (_type_): _description_

    Returns:
        _type_: _description_
    """
    print('per_protocol_analysis_tshark')
    # protocol = 'multicast'
    # mc_packets = protocol_filter(dict_dec, all_packets_results, protocol)

    # tcp_packets = protocol_filter(dict_dec, all_packets_results, protocol)
    
    new_packets = protocol_filter(dict_dec, all_packets_results, pcap_filter)
    return protocols_analysis_tshark(out_dir, dict_dec, new_packets, pcap_filter)

if __name__ == "__main__":
    main()
    # return 0 
    