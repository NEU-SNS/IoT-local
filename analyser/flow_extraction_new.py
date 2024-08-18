import sys
import os
import ipaddress
import numpy as np
import csv


feature_header = ['time_epoch', 'time_delta', 'protocol', 'trans_port', 'dst', 'sport', 'dport', 'packet_length', 'inbound (bool)']

def extract_single(packets):
        """Extract flows by 5-tuple
            Parameters
            ----------
            packets : np.array of shape=(n_samples, n_features)
                Numpy array containing packets.
            Returns
            -------
            result : dict
                Dictionary of 3_tuple or 5_tuple -> packets
                3 tuple is defined as (highest_protocol, src, dst)
                5 tuple is defined as (trans_proto, src, sport, dst, dport)
                
                (protocol, dst, sport, dport)

            """
        # Initialise result
        result = dict()

        # Extract burst timestamp
        # timestamp = burst[0, 1]4321

        packets = np.array(packets)
        # Loop over packets in burst
        for packet in packets:

            # Define key as 5-tuple or 3-tuple if layer 3 and below
            key = key_generate(packet)
            if key[0] == 0:
                # print(packet)
                continue
            # Set length depending on incoming or outgoing
            # length = -packet[5] if incoming else packet[5]

            # Add length of packet to flow
            result[key] = result.get(key, [])
            result[key].append(packet)

        # Convert lengths to numpy array.
        result = {k: np.array(v) for k, v in result.items()}

        # # TODO: need to refactor this part. May cause slightly inaccurate burst partition without it. 
        # # remove retrans and dup
        # result = rm_retrans_dup(result)

        # Return result
        return result

def layer_4_below(s_port, d_port):
    # if len(packet)<8:
    #     return True
    if s_port == '0' and d_port == '0':
        # print(packet, packet[7])
        return True
    return False

def rm_retrans_dup(results):
    """Remove retransmission and duplicated packets and their impact to timing
    Parameters
    ----------
    results : Dictionary of 5_tuple -> packets
        5 tuple is defined as (trans_proto, src, sport, dst, dport)
    Returns
    -------
    results : 
        Dictionary of 5_tuple -> packets
        5 tuple is defined as (trans_proto, src, sport, dst, dport)

    """
    print('Rm_retrans_dup ', len(results.keys()))
    for k in results.keys():
        # print(k)
        ts = results[k][:, 1]
        ts = ts.astype(np.float)
        # diff = results[k][:, 2]
        diff = [0] + [(ts[i + 1] - ts[i]) for i in range(len(ts)-1)]
        diff = np.array(diff)

        # print('Diff: ', diff)
        results[k][:, 2] = np.round(diff, 6)
        # print('Res: ', results[k][:, 2])
        # flagged = 0
        # ts = 0
        filter_retrans = []
        # print('1')
        for l in range(len(results[k])):
            packet = results[k][l]
            # print('2')
            if len(packet) != 14:
                print(packet)
                filter_retrans.append(False)
                continue
            # print('3')
            expert_info = packet[-2]
            if expert_info != "" and ('retransmission' in expert_info or 'Duplicate ACK' in expert_info):
                # print(packet)
                # flagged = 1
                # ts = packet[1]
                filter_retrans.append(False)
            else:
                filter_retrans.append(True)
            # print('4')

        # tmp = []
        # for i in range(len(filter_retrans)):
        #     if filter_retrans[i] == True:
        #         tmp.append(results[k][i])
        results[k] = results[k][filter_retrans]
        # print('WTF?')
        # try:
        #     results[k] = np.array(tmp)
        #     print(len(results[k]))
        # except Exception as e:
        #     print(str(e))
        #     print('Error')
        #     exit(1)
        # print(len(results[k]))
        # print('retrans filtered..',results[k].shape)
        # print(results[k])
        results[k] = np.delete(results[k],-2,1)
        # print(results[k])
        # print('retrans info deleted..', results[k].shape)
    
    return results



def key_generate(packet):
    """ Extract the key of a packet and check whether it is incoming or
        outgoing.
        Parameters
        ----------
        # timestamp : float
        #     Timestamp of burst.
        packet : np.array of shape=(n_features)
    
        Returns
        -------
        key : tuple
            Key 5-tuple of flow.
        # incoming : boolean
        #     Boolean indicating whether flow is incoming.
        """
    # Define key as 5-tuple (trans_proto, dst, sport , dport)
    try:
        key = (packet[3], packet[4], packet[5], packet[6]) #  
    except:
        return (0,0,0,0) # 

    # Return result
    return key


def burst_split_onlyudp(flow_dic, threshold=1):
    """only split udp traffic
        ----------
        flow_dic : dict, key: tuple, value: packets
        threshold : float, default=1
            Burst threshold in seconds.
        Returns
        -------
        result : dict{ key: tuple, value: dict{key: ts, value: packets} }
            List of np.array, where each list entry are the packets in a
            burst.
        """
    # Initialise result
    result = {}
    for k, v in flow_dic.items(): # k: (trans_proto, dst, sport , dport)
        if layer_4_below(k[2],k[3]):
            continue
        elif k[0] == 'tcp':
            result[k] = result.get(k,{})
            result[k][v[0,0].astype(np.float64)] = v[:] # 
            continue
        # Compute difference between packets
        if len(v) < 2:
            continue
        ts = v[:, 0]
        diff = v[:, 1]
        ts = ts.astype(np.float64)
        try:
            # diff = diff.astype(np.float)
            
            diff = [0] + [(ts[i + 1] - ts[i]) for i in range(len(ts)-1)]
            diff = np.array(diff)
        except ValueError:
            print('Time diff error: ', k, ts, diff, v[:,4])
            with open('./decoded_idle_error.txt', "a+") as errff:
                errff.write('Time diff error: ')
                errff.write('%s\n' %( ','.join(v[0,4])))
            # exit(1)
            continue

        
        result[k] = result.get(k,{})

        # Select indices where difference is greater than threshold
        indices_split = np.argwhere(diff > threshold)
        # Add 0 as start and length as end index
        indices_split = [0] + list(indices_split.flatten()) + [v.shape[0]]
        for start, end in zip(indices_split, indices_split[1:]):
            if end == 0:
                # print("end == 0",indices_split)
                continue
            result[k][ts[start]] = result[k].get(ts[start],[])
            result[k][ts[start]] = v[start:end]
            result[k][ts[start]][0,1] = float(0.0)

    # Return result
    return result
    
def burst_split(flow_dic, threshold=1):
    """Split packets in bursts based on given threshold.
        A burst is defined as a period of inactivity specified by treshold.
        Parameters
        ----------
        flow_dic : dict, key: tuple, value: packets
        threshold : float, default=1
            Burst threshold in seconds.
        Returns
        -------
        result : dict{ key: tuple, value: dict{key: ts, value: packets} }
            List of np.array, where each list entry are the packets in a
            burst.
        """
    # Initialise result
    result = {}
    for k, v in flow_dic.items():
        
        # Compute difference between packets
        if len(v) < 2:
            continue
        ts = v[:, 0]
        diff = v[:, 1]
        ts = ts.astype(np.float)
        try:
            # diff = diff.astype(np.float)
            
            diff = [0] + [(ts[i + 1] - ts[i]) for i in range(len(ts)-1)]
            diff = np.array(diff)
        except ValueError:
            print('Time diff error: ', k, ts, diff, v[:,4])
            with open('./decoded_idle_error.txt', "a+") as errff:
                errff.write('Time diff error: ')
                errff.write('%s\n' %( ','.join(v[0,4])))
            # exit(1)
            continue

        
        result[k] = result.get(k,{})

        # Select indices where difference is greater than threshold
        indices_split = np.argwhere(diff > threshold)
        # Add 0 as start and length as end index
        indices_split = [0] + list(indices_split.flatten()) + [v.shape[0]]
        for start, end in zip(indices_split, indices_split[1:]):
            if end == 0:
                # print("end == 0",indices_split)
                continue
            result[k][ts[start]] = result[k].get(ts[start],[])
            result[k][ts[start]] = v[start:end]
            result[k][ts[start]][0,1] = float(0.0)

    # Return result
    return result

def flows_burst_output(results, out_dir, device):
    if not os.path.exists(out_dir):
        os.system('mkdir -pv %s' % out_dir)
        
    out_file = os.path.join(out_dir, '%s.csv' % device)
    
    output = []
    for key, v in results.items():
        # key = (protocol, dst, sport, dport), sport dport = 0 if layer 3 or below
        for ts, packets in v.items():
            tmp_volume = 0
            highest_protocol = set()
            for p in packets:
                tmp_volume += int(p[-2])
                highest_protocol.add(p[2])
            highest_protocol = sorted(list(highest_protocol))
            cur_flow = [ts, key[0], key[1], key[2], key[3], ';'.join(highest_protocol), len(packets), tmp_volume, packets[0][-1]]
            output.append(cur_flow)

    # try:
    output = sorted(output, key=lambda x: x[0])
    # except TypeError as e:
    #     # print(np.array(output)[:,0])
    #     print("TypeError: ", device, e)
    #     with open(out_file, 'w') as f:
    #         write = csv.writer(f)
    #         write.writerow(['timestamp', 'trans_protocol', 'dst', 'device_port', 'remote_port', 'highest_protocol', 'flow_length', 'volume', 'inbound'])
    #         write.writerows(output)
    #     exit(1)
    
    with open(out_file, 'w') as f:
        write = csv.writer(f)
        write.writerow(['timestamp', 'trans_protocol', 'dst', 'device_port', 'remote_port', 'highest_protocol', 'flow_length', 'volume', 'inbound'])
        write.writerows(output)

def flows_output(results, out_dir, device):
    
    # dict { key: tuple, value: packets}
    if not os.path.exists(out_dir):
        os.system('mkdir -pv %s' % out_dir)
        
    out_file = os.path.join(out_dir, '%s.csv' % device)
    
    output = []
    for key, packets in results.items():
        # key = (protocol, dst, sport, dport), sport dport = 0 if layer 3 or below
        if key[2] == '0' :   # below layer 4 
            continue
        ts = packets[0][0]

        tmp_volume = 0
        highest_protocol = set()
        for p in packets:
            tmp_volume += int(p[-2])
            highest_protocol.add(p[2])
        highest_protocol = sorted(list(highest_protocol))
        cur_flow = [ts, key[0], key[1], key[2], key[3], ';'.join(highest_protocol), len(packets), tmp_volume, packets[0][-1]]
        output.append(cur_flow)

    # try:
    output = sorted(output, key=lambda x: x[0])
    # except TypeError as e:
    #     # print(np.array(output)[:,0])
    #     print("TypeError: ", device, e)
    #     with open(out_file, 'w') as f:
    #         write = csv.writer(f)
    #         write.writerow(['timestamp', 'trans_protocol', 'dst', 'device_port', 'remote_port', 'highest_protocol', 'flow_length', 'volume', 'inbound'])
    #         write.writerows(output)
    #     exit(1)
    
    with open(out_file, 'w') as f:
        write = csv.writer(f)
        write.writerow(['timestamp', 'trans_protocol', 'dst', 'device_port', 'remote_port', 'highest_protocol', 'flow_length', 'volume', 'inbound'])
        write.writerows(output)

def flows_output_withicmp(results, out_dir, device):
    
    # dict { key: tuple, value: packets}
    if not os.path.exists(out_dir):
        os.system('mkdir -pv %s' % out_dir)
        
    out_file = os.path.join(out_dir, '%s.csv' % device)
    
    output = []
    for key, packets in results.items():
        # key = (protocol, dst, sport, dport), sport dport = 0 if layer 3 or below
        if key[2] == '0' and key[0] != 'icmp':   # below layer 4 and not icmp
            continue
        ts = packets[0][0]

        tmp_volume = 0
        highest_protocol = set()
        for p in packets:
            tmp_volume += int(p[-2])
            highest_protocol.add(p[2])
        highest_protocol = sorted(list(highest_protocol))
        cur_flow = [ts, key[0], key[1], key[2], key[3], ';'.join(highest_protocol), len(packets), tmp_volume, packets[0][-1]]
        output.append(cur_flow)

    # try:
    output = sorted(output, key=lambda x: x[0])
    # except TypeError as e:
    #     # print(np.array(output)[:,0])
    #     print("TypeError: ", device, e)
    #     with open(out_file, 'w') as f:
    #         write = csv.writer(f)
    #         write.writerow(['timestamp', 'trans_protocol', 'dst', 'device_port', 'remote_port', 'highest_protocol', 'flow_length', 'volume', 'inbound'])
    #         write.writerows(output)
    #     exit(1)
    
    with open(out_file, 'w') as f:
        write = csv.writer(f)
        write.writerow(['timestamp', 'ip.proto', 'dst', 'device_port', 'remote_port', 'highest_protocol', 'flow_length', 'volume', 'inbound'])
        write.writerows(output)