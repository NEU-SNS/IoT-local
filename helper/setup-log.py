import os
import json 

"""
scp tianrui@129.10.227.207:/opt/moniotr/log/setup-device.log .
"""

def filter_setup_log():
    list_lines = []
    with open('setup-device.log', 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith('2023-05-1'):
                list_lines.append(line)

    with open('new-setup-device3.log', 'w') as f:
        for line in list_lines:
            if line.startswith('2023-05-10') or line.startswith('2023-05-11') or line.startswith('2023-05-12'):
                # or line.startswith('2023-04-13') or line.startswith('2023-04-14')  or line.startswith('2023-04-15'):
                
            # if line.startswith('2022-12-23') and int(line.split(' ')[1].split(':')[0]) < 21:
            #     continue
            # if line.startswith('2022-12-28') and int(line.split(' ')[1].split(':')[0]) >= 21:
            #     continue
                f.write(line)
            else:
                continue

def get_device_ip():
    out_file='/home/hutr/local-traffic-analysis/outputs/devices_ip_2023May.txt'
    device_ip_dict = {}
    ip_dict = {}
    with open('new-setup-device3.log', 'r') as f:
        lines = f.readlines()
        for line in lines:
            tmp = line.split(' ')
            day = tmp[0]
            time = tmp[1]
            ip = tmp[4]
            device_name = tmp[6]
            time = day + ' ' + time
            ip_short = ip.split('.')[-1]
            
            # ip_dict = {ip: {dev: start_time}}
            if ip_short not in ip_dict:
                ip_dict[ip_short] = {device_name:time}
            else:
                if device_name not in ip_dict[ip_short]:
                    ip_dict[ip_short][device_name] = time
            
            if device_name == '' or device_name == ' ':
                device_name = tmp[5]
            if device_name not in device_ip_dict:
                device_ip_dict[device_name] = []
                device_ip_dict[device_name].append([time, ip])
            else:
                if ip != device_ip_dict[device_name][-1][-1]:
                    device_ip_dict[device_name].append([time, ip])
                else:
                    continue
    
    print('IP set: ', len(ip_dict))
    for k,v in ip_dict.items():
        print(k,v)
    with open('ip_dict_2023May.txt', 'w') as f:
        f.write(json.dumps(ip_dict, indent=4))
    with open(out_file, 'w') as f:
        f.write(json.dumps(device_ip_dict, indent=4))

    # for k in device_ip_dict:
    #     print(k, len(device_ip_dict[k]))
    
    # ordered_device_ip = []
    # for k,v in device_ip_dict.items():
    #     ordered_device_ip.append([k,len(v)])
    # ordered_device_ip = sorted(ordered_device_ip, key=lambda t: t[1],reverse=True)
    # for i in ordered_device_ip:
    #     print(i[0], i[1])

    
filter_setup_log()
get_device_ip()
