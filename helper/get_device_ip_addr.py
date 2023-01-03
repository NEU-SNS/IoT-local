"""This file is deprecated. The implementation is wrong. DO NOT USE. 

Returns:
    _type_: _description_
"""
# import os

# out_file='/home/hutr/local-traffic-analysis/helper/devices_ip.txt'

# def read_device_ip():
#     ip_file = out_file
#     ip_dic = {}
#     with open(ip_file, 'r') as f:
#         lines = f.readlines()
#         for line in lines:
#             if line.startswith(' ') or line.startswith('/n'):
#                 continue
#             # print(line[:-1])
#             tmp_ip, tmp_device = line[:-1].split(' ')
#             if len(tmp_ip) != 14:
#                 print(tmp_ip, tmp_device)
#                 exit(1)

#             ip_dic[tmp_device] = tmp_ip
#     # print(mac_dic)
#     return ip_dic


# base_dir = '/home/hutr/2022-datasets/idle-dataset/'
# deivces_list = os.listdir(base_dir)
# device_ip = {}
# for device in deivces_list:
#     files = os.listdir(os.path.join(base_dir, device))
#     ip_list = []
#     for pcap in files:
#         cur_ip = str(pcap).split('_')[-1][:-5]
#         ip_list.append(cur_ip)
#     ip_set = set(ip_list)
#     if len(ip_set) > 1:
#         print(device, ip_set)
#     else:
#         device_ip[device] = str(list(ip_set)[0])

# with open(out_file, 'w') as ff:
#     for device in device_ip:
#         ff.write('%s %s\n' % (device_ip[device], device))


# print(list(read_device_ip().values()))