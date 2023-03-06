import os
import json


def parse_multicast_logfiles(out_dir):
    print('parsing multicast output')
    cur_out_dir = os.path.join(out_dir, 'protocols','multicast/')
    out_file = os.path.join(out_dir, 'protocols','multicast_info.txt')
    if not os.path.isdir(cur_out_dir):
        print('Parse multicast: Not a dir ', cur_out_dir)

    multicast_add_count = {}
    for dev_file in os.listdir(cur_out_dir):
        if not dev_file.endswith('.txt'):
            continue
        print(dev_file)
        dev_name = dev_file.split('.')[0]
        with open(os.path.join(cur_out_dir,dev_file)) as f:
            lines = f.readlines()
            count = 0
            for line in lines:
                if line!='\n' or line!="":
                    count += 1
            multicast_add_count[dev_name] = count
        
    # print(request_info_list)
    with open(out_file, 'w') as f:
        ordered_multicast_address_count = []
        for k,v in multicast_add_count.items():
            # print(k.strip(),':', v)
            ordered_multicast_address_count.append([k,v])
        ordered_multicast_address_count = sorted(ordered_multicast_address_count, key=lambda t: t[1],reverse=True)
        for i in ordered_multicast_address_count:
            f.write('%s: %d\n' %(i[0].strip(), i[1]))
            # for j in request_info_list[i[0]]:
            #     f.write('%s ' % j)
            # f.write('\n\n')
        # f.write(json.dumps(request_info_list, indent=4))
        # f.write('\n\n')
        # f.write(json.dumps(client_id, indent=4)
    

out_dir = '/home/hutr/local_output/idle-dataset-dec'
parse_multicast_logfiles(out_dir)