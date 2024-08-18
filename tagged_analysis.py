from analyser.utils import *
from analyser.flow_extraction import extract_single, burst_split
import analyser.plotting as plotting
# from analyser.extract_ca import analyzePacket
from analyser.protocols_analysis import * 
from analyser.all_device_analysis import * 
from analyser.vis import *
from analyser.protocol_identification import * 
from analysis import pyshark_idle_input_threading

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
        # if device != 'echodot3c':  # and device != 'google-home-mini'
        #     continue
        # if not device.startswith('echodot3'):
        #     continue
        if device not in dict_dec:
            dict_dec[device] = []
        full_dev_dir = os.path.join(in_dir, dev_dir)
        for activity_dir in os.listdir(full_dev_dir):
            # if activity_dir == 'power':
            #     continue
            for dec_file in os.listdir(os.path.join(full_dev_dir, activity_dir)):
                full_dec_file = os.path.join(full_dev_dir, activity_dir, dec_file)
                if not full_dec_file.endswith(".pcap"):
                    print(c.WRONG_EXT % ("input file", "PCAP", full_dec_file), file=sys.stderr)
                    continue
                if not os.access(full_dec_file, os.R_OK):
                    print(c.NO_PERM % ("input file", full_dec_file, "read"), file=sys.stderr)
                    continue
                dict_dec[device].append(full_dec_file)

    # for k in dict_dec:
    #     print(k, len(dict_dec[k]))
    # exit(1)

    """
    input and output
    """

    # # * all packets 
    # pcap_filter = "not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission and not tcp.analysis.lost_segment"
    # # pcap_filter = "not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission"
    # pcap_filter = 'frame.time>="2022-08-25 12:00:00" and frame.time<="2022-08-29 11:59:59"'
    pcap_filter = ""
    
    


    if cur_filter != "" and addressing_method_filter != "":
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
        
        

if __name__ == "__main__":
    main()
    # return 0 
    