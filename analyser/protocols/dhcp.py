import os
import json


def parse_dhcp_logfiles(out_dir):
    print('parsing dhcp output')
    cur_out_dir = os.path.join(out_dir, 'protocols','dhcp/')
    out_file = os.path.join(out_dir, 'protocols','dhcp_info.txt')
    if not os.path.isdir(cur_out_dir):
        print('Parse dhcp: Not a dir ', cur_out_dir)
    # print(os.path.isdir(cur_out_dir))
    # print(os.listdir(cur_out_dir))
    request_info_list = {}
    client_id = {}
    for dev_file in os.listdir(cur_out_dir):
        if not dev_file.endswith('.txt'):
            continue
        print(dev_file)
        dev_name = dev_file.split('.')[0]
        with open(os.path.join(cur_out_dir,dev_file)) as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith('Vendor class'):
                    vendor_class_id = line.strip().split(':')[1]
                    # vendor_class_id = vendor_class_id
                    client_id[vendor_class_id] = client_id.get(vendor_class_id, set())
                    client_id[vendor_class_id].add(dev_name)
                    # client_id[vendor_class_id] = client_id.get(vendor_class_id, 0) + 1
                if line.startswith(' ('):
                    request_info_list[line] = request_info_list.get(line, set())
                    request_info_list[line].add(dev_name)
                    # request_info_list[line] = request_info_list.get(line, 0) + 1
    
    # print(request_info_list)
    with open(out_file, 'w') as f:
        ordered_request_info_list = []
        for k,v in request_info_list.items():
            # print(k.strip(),':', v)
            ordered_request_info_list.append([k,len(v)])
        ordered_request_info_list = sorted(ordered_request_info_list, key=lambda t: t[1],reverse=True)
        for i in ordered_request_info_list:
            f.write('%s: %d\n' %(i[0].strip(), i[1]))
            for j in request_info_list[i[0]]:
                f.write('%s ' % j)
            f.write('\n\n')
        # f.write(json.dumps(request_info_list, indent=4))
        f.write('\n\n')
        # f.write(json.dumps(client_id, indent=4))
        
        ordered_client_id = []
        for k,v in client_id.items():
            ordered_client_id.append([k,len(v)])
        ordered_client_id = sorted(ordered_client_id, key=lambda t: t[1],reverse=True)
        for i in ordered_client_id:
            f.write('%s: %d\n' %(i[0], i[1]))
            
            for j in client_id[i[0]]:
                f.write('%s ' % j)
            f.write('\n\n')
    

out_dir = '/home/hutr/local_output/idle-dataset-dec'
parse_dhcp_logfiles(out_dir)