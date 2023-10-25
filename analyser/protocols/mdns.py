from analyser.utils import *

def mdns_analysis(out_dir, dict_dec, packets_dict):
    cur_out_dir = os.path.join(out_dir, 'protocols','mdns')
    v4_count = {}
    v6_count = {}
    query_count = {}
    response_count = {}
    unique_query_count = {}
    unique_response_count = {}
    
    for device in dict_dec:
        print('analyzing MDNS packets...', device) # os.getpid()
        if device not in packets_dict:
            continue
        
        query_records = {}
        response_records = {}
        type_dict = {'1':'A', '2':'NS', '5':'CNAME', '12':'PTR','16':'TXT', '28':'AAAA', '33':'SRV', '255':'ANY'}
        for packet in packets_dict[device]:
            # print(packet)

            dst_mac = packet.eth.dst
            src_mac = packet.eth.src
            # print(src_mac, dst_mac)
            if dst_mac.startswith('33:33'):
                v6_count[device] = v6_count.get(device, 0) + 1
            else:
                v4_count[device] = v4_count.get(device, 0) + 1
            
            
            if packet.mdns.dns_flags_response == '0':
                query_count[device] = query_count.get(device, 0) + 1
                
                if int(packet.mdns.dns_count_queries) > 1:
                    for line in packet.mdns._get_all_field_lines():
                        # if line.strip().startswith('Name:'):
                        if re.match('(.*)(: type)(.*)(, class)(.*)', line) != None:
                            # print(line.strip())
                            qry_name = line.strip().split(':')[0].strip()
                            qry_type = line.strip().split(':')[1].split(',')[0].strip().split(' ')[1]
                            query_records[(qry_name, qry_type)] = query_records.get((qry_name, qry_type), 0) + 1
                            
                else:
                    try:
                        qry_name = packet.mdns.dns_qry_name
                        qry_type = packet.mdns.dns_qry_type
                        if qry_type in type_dict:
                            qry_type = type_dict[qry_type]
                        query_records[(qry_name, qry_type)] = query_records.get((qry_name, qry_type), 0) + 1
                    except:
                        pass
                        
                
            else:
                response_count[device] = response_count.get(device, 0) + 1
                
                for line in packet.mdns._get_all_field_lines():
                    # if line.strip().startswith('Name:'):
                    if re.match('(.*)(: type)(.*)(, class)(.*)', line) != None:
                        resp_name = line.strip().split(':')[0].strip()
                        try:
                            resp_type = line.strip().split(': ')[1].split(',')[0].strip().split(' ')[1]
                        except: 
                            print(line)
                            exit(1)
                        resp_addr = line.strip().split()[-1]
                        response_records[(resp_name, resp_type, resp_addr)] = response_records.get((resp_name, resp_type, resp_addr), 0) + 1

                
        if not os.path.exists(cur_out_dir):
            os.system('mkdir -pv %s' % cur_out_dir)
        out_file = os.path.join(cur_out_dir, '%s.txt' % device)
        
        unique_query_count[device] = len(query_records)
        unique_response_count[device] = len(response_records)
        with open(out_file, 'w') as f:
            # sorted_query_records = sorted([(k,v) for k,v in query_records.items()], key=lambda t:t[1], reverse=True)
            f.write('Query: %d\n' % len(query_records))
            for i in query_records:
                f.write('%s: %d\n' % (i, query_records[i]))    
            
            # sorted_query_records = sorted([(k,v) for k,v in query_records.items()], key=lambda t:t[1], reverse=True)
            f.write('\n\nResponse: %d\n' % len(response_records))
            for i in response_records:
                f.write('%s: %d\n' % (i, response_records[i]))   
            
    return_list = []
    for device in dict_dec:
        # count += 1
        print(device, v4_count.get(device, 0), v6_count.get(device, 0), query_count.get(device, 0), response_count.get(device, 0))
        return_list.append([device, v4_count.get(device, 0), v6_count.get(device, 0), query_count.get(device, 0),  unique_query_count.get(device, 0), response_count.get(device, 0), unique_response_count.get(device, 0)])
    header = ['device', 'v4_count', 'v6_count',  'query_count', 'unique_query_count', 'response_count', 'unique_response_count']
    return (header, return_list) 

    