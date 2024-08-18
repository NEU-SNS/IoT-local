from analyser.utils import *

def http_analysis(out_dir, dict_dec, packets_dict):
    
    cur_out_dir = os.path.join(out_dir, 'protocols','http')
    
    # get_count = {}
    # post_count = {}
    request_count = {}
    get_count = {}
    post_count = {}
    response_count = {}
    mac_dic = read_mac_address()
    # ssdp&&!icmp
    for device in dict_dec:

        if device not in packets_dict:
            print('No HTTP Device: %s' % device)
            continue
        print('analyzing HTTP packets...', device)
        
        my_device_mac = mac_dic[device]
        
        
        request_method = {}
        request_uri = {}
        request_version = {}
        request_user_agent = {}
        # target_device = {}
        # request_header = {}
        # request_location = {}
        # request_server = {}
        
        response_code = {}
        response_version = {}
        response_server = {}
        
        # response_header = {}
        # response_location = {}
        
        # request_method = {}

        count = 0 
        
        for packet in packets_dict[device]:
            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            
            if src_mac == my_device_mac:
                # tcp ack packet filter
                if len(packet.layers) <= 3:
                    continue
                
                tmp_all_fields = packet.http._all_fields
                # requests
                if 'http.request' in tmp_all_fields:
                    request_count[device] = request_count.get(device, 0) + 1 
                    
                    if packet.http.request_method == 'GET':
                        get_count[device] = get_count.get(device, 0) + 1
                    elif packet.http.request_method == 'POST':
                        post_count[device] = post_count.get(device, 0) + 1
                    
                    request_method[packet.http.request_method] = request_method.get(packet.http.request_method, 0) + 1
                    if 'http.request.full_uri' in tmp_all_fields:
                        request_uri[packet.http.request_full_uri] = request_uri.get(packet.http.request_full_uri, 0) + 1
                    # request_info[packet.http.chat]
                    
                    if 'http.request.version' in tmp_all_fields:
                        request_version[packet.http.request_version] = request_version.get(packet.http.request_version, 0) + 1
                    
                    if 'http.user_agent' in tmp_all_fields:
                        request_user_agent[packet.http.user_agent] = request_user_agent.get(packet.http.user_agent, 0) + 1
                elif 'http.response' in tmp_all_fields:
                    response_count[device] = response_count.get(device, 0) + 1 
                    
                    response_code[packet.http.response_code] = response_code.get(packet.http.response_code, 0) + 1
                    # packet.http.chat
                    if 'http.response.version' in tmp_all_fields:
                        response_version[packet.http.response_version] = response_version.get(packet.http.response_version, 0) + 1
                    if 'http.server' in tmp_all_fields: 
                        response_server[packet.http.server] = response_server.get(packet.http.server, 0) + 1
                    # packet.http.file_data
            
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        with open(out_file, 'w') as f:
            # request method
            if len(request_method) != 0:
            
                for i, j in request_method.items():
                    f.write('Request method %s: %d\n' % (i, j))
            
            for i, j in request_uri.items():
                f.write('Request full uri %s: %d\n' % (i, j))
            

            if len(request_version) != 0:
                for i, j in request_version.items():
                    f.write('Request version %s: %d\n' % (i, j))
            if len(request_user_agent) != 0:
                for i, j in request_user_agent.items():
                    f.write('Request UA %s: %d\n' % (i, j))
            # response:
            f.write('\n')
            # response code
            # sorted_response_code = sorted([(k,v) for k,v in response_code.items()], key=lambda t:t[1], reverse=True)
            if len(response_code) != 0:
                for i, j in response_code.items():
                    f.write('Response code %s: %d\n' % (i, j))
            if len(response_version) != 0:
                
                for i, j in response_version.items():
                    f.write('Response version %s: %d\n' % (i, j))
                    # f.write('%s\n' % lo)
            if len(response_server) != 0:
                for i, j in response_server.items():
                    f.write('Response server %s: %d\n' % (i, j))

    
    return_list = []
    for device in dict_dec:
        # count += 1
        print(device, request_count.get(device, 0), get_count.get(device, 0), post_count.get(device, 0), response_count.get(device, 0))
        if (request_count.get(device, 0) + response_count.get(device, 0) ) == 0:
            continue
        return_list.append([device, request_count.get(device, 0), get_count.get(device, 0), post_count.get(device, 0), response_count.get(device, 0)])
        
    header = ['device', 'request_count', 'get_count', 'post_count', 'response_count']
    return (header, return_list)
