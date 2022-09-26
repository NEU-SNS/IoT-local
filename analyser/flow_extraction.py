import sys
import os
import ipaddress
import numpy as np


feature_header = ['number', 'time_epoch', 'time_delta', 'len (size)', 'src mac', 'dst mac', 'Protocol', 'layer 4 protocol code (optional)', 
                    'TCP/UDP stream (optional)', 'src ip (optional)', 'dst ip (optional)', 'src port (optional)', 'dst port (optional)']

def extract_single(pcap):
        """Extract flows by 5-tuple
            Parameters
            ----------
            pcap : np.array of shape=(n_samples, n_features)
                Numpy array containing packets.
            Returns
            -------
            result : dict
                Dictionary of 5_tuple -> packets
                5 tuple is defined as (trans_proto, src, sport, dst, dport)

            """
        # Initialise result
        result = dict()

        # Extract burst timestamp
        # timestamp = burst[0, 1]


        # Loop over packets in burst
        for packet in pcap:
            # remove layer 4 below traffic:
            if layer_4_below(packet):
                continue

            # Define key as 5-tuple (trans_proto, src, sport, dst, dport)
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

def layer_4_below(packet):
    if len(packet)<8:
        return True
    #  IPv6 probably ok 
    if packet[7] != '6' and packet[7] != '17':
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
        # Define key as 5-tuple (trans_proto, src, sport, dst, dport)
        try:
            key = (packet[7], ipaddress.ip_address(packet[9]), packet[11],
                            ipaddress.ip_address(packet[10]), packet[12]) #  
        except:
            return (0,0,0,0,0) # 

        # Check if flow message is incoming
        if key[3].is_private and (key[1].is_private == False):
            incoming = True
            key = (key[0], key[3], key[4], key[1], key[2])
        elif key[3].is_private and key[1].is_private:
            if key[3] > key[1]:
                key = (key[0], key[3], key[4], key[1], key[2])

        # If incoming, return incoming key
        # if incoming:
        #     key = (key[0], key[3], key[4], key[1], key[2])

        # Set IP addresses to string
        key = (key[0], str(key[1]), key[2], str(key[3]), key[4])

        # Return result
        return key

def burst_split(flow_dic, threshold=1):
        """Split packets in bursts based on given threshold.
            A burst is defined as a period of inactivity specified by treshold.
            Parameters
            ----------
            flow_dic : dict, key: 5tuple, value: packets
            threshold : float, default=1
                Burst threshold in seconds.
            Returns
            -------
            result : dict{ key: 5tuple, value: dict{key: ts, value: packets} }
                List of np.array, where each list entry are the packets in a
                burst.
            """
        # Initialise result
        result = {}
        for k, v in flow_dic.items():
            
            # Compute difference between packets
            if len(v) < 2:
                continue
            ts = v[:, 1]
            diff = v[:, 2]
            # ts = ts.astype(np.float)
            try:
                diff = diff.astype(np.float)
                # diff2 = [0] + [(ts[i + 1] - ts[i]) for i in range(len(ts)-1)]
                diff = np.array(diff)
            except ValueError:
                print('Time diff error: ', k, ts, diff, v[:,-1])
                with open('./decoded_idle_error.txt', "a+") as errff:
                    errff.write('Time diff error: ')
                    errff.write('%s %s\n' %(v[0,-1], v[1,-1]))
                # exit(1)
                continue
            # try:
            #     ts = v[:, 1]
            #     # diff = v[:, 2]    # some samples only have one packet??? 
            #     # ! cause a bug
            #     ts = ts.astype(np.float)
            #     diff = [0] + [(ts[i + 1] - ts[i]) for i in range(len(ts)-1)]
            #     diff = np.array(diff)
            # except:
            #     print('time diff error: ', k, len(v))
            #     print()
            #     ts = ts.astype(np.float)
            #     diff = [0] + [(ts[i + 1] - ts[i]) for i in range(len(ts)-1)]
            #     diff = diff.astype(np.float)
            #     return result
            
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
                result[k][ts[start]][0,2] = float(0.0)

        # Return result
        return result
