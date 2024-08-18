from analyser.utils import *

def ssdp_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','ssdp')
    
    unicast_count = {}
    multicast_count = {}
    request_count = {}
    reply_count = {}
    mac_dict = read_mac_address()
    # ssdp&&!icmp
    for device in dict_dec:
        if 'honeypot' in device:
            if 'imdea' in device:
                tmp_device = 'imdea-pi'
            else:
                tmp_device = 'iotvm-local'
        my_device_mac = mac_dict[tmp_device]
        if device not in packets_dict:
            print('No SSDP Device: %s' % device)
            continue
        print('analyzing SSDP packets...', device)
        
        # target_device = {}
        request_info = {}
        request_method = {}
        request_header = {}
        request_location = {}
        request_server = {}
        request_identifier={}
        response_code = {}
        response_header = {}
        response_location = {}
        response_server = {}
        response_identifier={}
        count = 0 
        
        for packet in packets_dict[device]:
            # print(packet.ssdp._all_fields)
            if ("icmp" in str(packet.layers).lower()):
                continue
            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            request = 0
            # mutlicast requests
            if is_multicast(dst_mac):
                multicast_count[device] = multicast_count.get(device, 0) + 1 
                request_count[device] = request_count.get(device, 0) + 1 
                # print(packet.ssdp._all_fields)

                tmp_request_method = packet.ssdp.http_request_method
                request_method[tmp_request_method] = request_method.get(tmp_request_method, 0) + 1
                    
                # print(packet.ssdp.http_request_method)
                # print(packet.ssdp.http_request_uri)
                # print(packet.ssdp.http_host)
                # print(packet.ssdp.http_request_full_uri)
                if tmp_request_method.strip() == 'NOTIFY':
                    request_location[packet.ssdp.http_location] = request_location.get(packet.ssdp.http_location, 0) + 1
                    try: 
                        request_server[packet.ssdp.http_server] = request_server.get(packet.ssdp.http_server, 0) + 1
                    except:
                        pass 
                request_info[packet.ssdp.http_request_full_uri] = request_info.get(packet.ssdp.http_request_full_uri, 0) + 1
                for line in packet.ssdp._get_all_field_lines():
                    line = line.strip()
                    if line.startswith('ST') or line.startswith('NT'):
                        request_header[line] = request_header.get(line, 0) + 1
                    if line.startswith('USN'):
                        request_identifier[line] = request_identifier.get(line, 0) + 1
                        # break
                
            else:
                
                
                if src_mac == my_device_mac:
                    # unicast 
                    unicast_count[device] = unicast_count.get(device, 0) + 1 

                    tmp_all_fields = packet.ssdp._all_fields
                    if 'http.request.method' in tmp_all_fields:
                        request_count[device] = request_count.get(device, 0) + 1 
                        request = 1
                    else:
                        reply_count[device] = reply_count.get(device, 0) + 1 
                    # try:
                    #     # if is request
                    #     if packet.ssdp.http_request_method:
                    #         request_count[device] = request_count.get(device, 0) + 1 
                    #         request = 1
                    # except:
                    #     # print(packet.ssdp.http_response_code)
                    #     # print(packet.ssdp.http_location)
                        # print(packet.ssdp.http_server)
                        
                   
                    if request == 1:
                        # unicast request 
                        tmp_request_method = packet.ssdp.http_request_method
                        request_method[tmp_request_method] = request_method.get(tmp_request_method, 0) + 1
                        request_info[packet.ssdp.http_request_full_uri] = request_info.get(packet.ssdp.http_request_full_uri, 0) + 1
                        if tmp_request_method.strip() == 'NOTIFY':
                            request_location[packet.ssdp.http_location] = request_location.get(packet.ssdp.http_location, 0) + 1
                            try:
                                request_server[packet.ssdp.http_server] = request_server.get(packet.ssdp.http_server, 0) + 1
                            except:
                                pass
                        for line in packet.ssdp._get_all_field_lines():
                            line = line.strip()
                            if line.startswith('ST') or line.startswith('NT'):
                                request_header[line] = request_header.get(line, 0) + 1
                            if line.startswith('USN'):
                                request_identifier[line] = request_identifier.get(line, 0) + 1

                    else:
                        # unicast response
                        response_code[packet.ssdp.http_response_code] = response_code.get(packet.ssdp.http_response_code, 0) + 1

                        for line in packet.ssdp._get_all_field_lines():
                            line = line.strip()
                            if line.startswith('ST') or line.startswith('NT'):
                                response_header[line] = response_header.get(line, 0) + 1
                            if line.startswith('USN'):
                                response_identifier[line] = response_identifier.get(line, 0) + 1

                        response_location[packet.ssdp.http_location] = response_location.get(packet.ssdp.http_location, 0) + 1
                        response_server[packet.ssdp.http_server] = response_server.get(packet.ssdp.http_server, 0) + 1
                
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            # request method
            if len(request_method) != 0:
                # sorted_request_method = sorted([(k,v) for k,v in request_method.items()], key=lambda t:t[1], reverse=True)
            
                for i, j in request_method.items():
                    f.write('Request method %s: %d\n' % (i, j))
            
            # request info
            # sorted_request_info = sorted([(k,v) for k,v in request_info.items()], key=lambda t:t[1], reverse=True)
            for i, j in request_info.items():
                f.write('Request full uri %s: %d\n' % (i, j))
            
            # request header
            sorted_request_header = sorted([(k,v) for k,v in request_header.items()], key=lambda t:t[1], reverse=True)
            # print(sorted_request_header)
            for i in sorted_request_header:
                f.write('Request contents %s: %d\n' % (i[0], i[1]))
            if len(request_location) != 0:
                for i, j in request_location.items():
                    f.write('Request location %s: %d\n' % (i, j))
            if len(request_server) != 0:
                for i, j in request_server.items():
                    f.write('Request server %s: %d\n' % (i, j))
            if len(request_identifier) != 0:
                for i, j in request_identifier.items():
                    f.write('Request id %s: %d\n' % (i, j))
            # response:
            f.write('\n')
            # response code
            # sorted_response_code = sorted([(k,v) for k,v in response_code.items()], key=lambda t:t[1], reverse=True)
            for i, j in response_code.items():
                f.write('Response code %s: %d\n' % (i, j))
            if len(response_location) != 0:
                
                for i, j in response_location.items():
                    f.write('Response location %s: %d\n' % (i, j))
                    # f.write('%s\n' % lo)
            if len(response_server) != 0:
                for i, j in response_server.items():
                    f.write('Response server %s: %d\n' % (i, j))
            if len(response_identifier) != 0:
                for i, j in response_identifier.items():
                    f.write('Response id %s: %d\n' % (i, j))
            # request header
            sorted_response_header = sorted([(k,v) for k,v in response_header.items()], key=lambda t:t[1], reverse=True)
            for i in sorted_response_header:
                f.write('Response contents %s: %d\n' % (i[0], i[1]))
    
    return_list = []
    for device in dict_dec:
        # count += 1
        print(device, unicast_count.get(device, 0), multicast_count.get(device, 0), request_count.get(device, 0), reply_count.get(device, 0))
        if (unicast_count.get(device, 0) + multicast_count.get(device, 0) ) == 0:
            continue
        return_list.append([device, unicast_count.get(device, 0), multicast_count.get(device, 0), request_count.get(device, 0), reply_count.get(device, 0)])
        
    header = ['device', 'unicast_count', 'multicast_count', 'request_count', 'reply_count']
    return (header, return_list)