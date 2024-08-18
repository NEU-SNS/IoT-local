import os 
import sys
import csv
import json
import threading
# from collections import Counter
import multiprocessing

"""
Who respond to the multicast/broadcast scanning

"""
def is_broadcast_or_multicast(address):
    return address.startswith('ff:ff:ff:ff:ff:ff') or \
           address.startswith('01:00:5e') or \
           address.startswith('33:33')

def process_device(input_dir, output_dir, tmp_dict_dev, response_get, respond_to, index):
    response_get[index] = {}
    respond_to[index] = {}
    for device_name in tmp_dict_dev:
        dev_file = device_name + '.csv'
        with open(os.path.join(input_dir,dev_file), 'r') as input_file, \
            open(os.path.join(output_dir, dev_file), 'w', newline='') as output_file:
            # Create a CSV reader for the input file
            input_reader = list(csv.DictReader(input_file))
            
            # Create a CSV writer for the output file
            output_writer = csv.writer(output_file)
            output_dict = {}
            
            response_get[index][device_name] = {}
            # input_header = 'timestamp,trans_protocol,dst,device_port,remote_port,highest_protocol,flow_length,volume,inbound'
            
            for i in range(len(input_reader)):
                row = input_reader[i]
                # Check if this flow is a broadcast or multicast\
                # print(row)
                if is_broadcast_or_multicast(row['dst']) and row['highest_protocol'] != 'dhcp':
                    # print(row['dst'])
                    # Loop over each subsequent row in the input file to find unicast responses
                    # response_flag = 0
                    for j in range(i+1, len(input_reader)):
                        response_row = input_reader[j]
                        # Check if this flow is a unicast response
                        if response_row['timestamp'] < row['timestamp']:
                            continue
                        elif float(response_row['timestamp']) > (float(row['timestamp']) + 3):
                            break
                        elif response_row['inbound'] == '1' and \
                            response_row['dst'] != 'router' and \
                            response_row['trans_protocol'] == row['trans_protocol'] and \
                            response_row['device_port'] == row['device_port']:
                                #  and response_row['remote_port'] == row['remote_port']
                            # # Write the broadcast/multicast flow and its unicast response to the output file
                            # output_dict.append((row['highest_protocol'], row['dst'],
                            #                         row['device_port'], row['remote_port'], response_row['dst']))
                            output_dict[(row['highest_protocol'], row['dst'],
                                                    row['device_port'], row['remote_port'], 
                                                    response_row['dst'])] = output_dict.get((row['highest_protocol'], row['dst'],
                                                    row['device_port'], row['remote_port'], 
                                                    response_row['dst']), 0) + 1
                            # print(float(row['timestamp']), float(response_row['timestamp']), response_row['dst'])
                            # output_writer.writerow([row['timestamp'], row['highest_protocol'], row['dst'],
                                                    # row['device_port'], row['remote_port'], response_row['dst']])
                            
                        

            # output_agg = Counter(output_dict)
            output_agg_list  = [(key, count) for key, count in output_dict.items()]
            # Sort the list by the count of instances in descending order
            output_agg_list.sort(key=lambda x: x[1], reverse=True)
            # Write the header row to the output file
            output_writer.writerow(['highest_protocol', 'dst', 'device_port', 'remote_port', 'response','count']) # 'remote_port',
            for key, count in output_agg_list:
                
                output_writer.writerow([key[0], key[1], key[2], key[3], key[4], count]) # 
                    
                response_get[index][device_name][key[-1]] = response_get[index][device_name].get(key[-1], 0) + count
                if key[-1] not in respond_to[index]:
                    respond_to[index][key[-1]] = {}
                respond_to[index][key[-1]][device_name] = respond_to[index][key[-1]].get(device_name, 0) + count
                

# Check if the script was called with the right number of arguments
if len(sys.argv) != 3:
    print('Usage: python script.py input_dir output_dir')
    sys.exit(1)

# Get the input and output directories from the command-line arguments
input_dir, output_dir = sys.argv[1:]

# Write the combined results to the output directory
if not os.path.exists(output_dir):
    os.mkdir(output_dir)

try:
    cpu_count = int(multiprocessing.cpu_count())
    num_thread = cpu_count-2
except:
    num_thread = 30
in_dev = [ [] for _ in range(num_thread) ]
index = 0 
    
        
for dev_file in os.listdir(input_dir): 
    if dev_file.startswith('_') or not dev_file.endswith('.csv'):
        continue
    device_name = dev_file.split('.')[0].strip()
    # if device_name != 'amcrest-cam-wired':
    #     continue
    # # print(device_name)
    # response_get[device_name] = {}
    in_dev[index % num_thread].append(device_name)
    index += 1
print('Multithreading... ', len(in_dev))
threads = [None] * num_thread
tmp_response_get = [None] * num_thread
tmp_respond_to = [None] * num_thread

for i in range(len(threads)):
    tmp_dict_dev = in_dev[i]
    if len(tmp_dict_dev) == 0:
        continue
    print('Thread %d:' % (i+1), tmp_dict_dev)
    threads[i] = threading.Thread(target=process_device, args=(input_dir, output_dir, tmp_dict_dev, tmp_response_get, tmp_respond_to, i))
    threads[i].start()

for i in range(len(threads)):
    if threads[i] == None:
        continue
    threads[i].join()

response_get = {}
respond_to = {}
for i in range(len(tmp_response_get)):
    if threads[i] == None:
        continue
    if not isinstance(tmp_response_get[i], dict):
        print('thread result is not a dict')
        continue
    response_get = response_get | tmp_response_get[i] 
for i in range(len(tmp_respond_to)):
    if threads[i] == None:
        continue
    if not isinstance(tmp_respond_to[i], dict):
        print('thread result is not a dict')
        continue
    for respond_dst in tmp_respond_to[i]:
        if not respond_dst in respond_to:
            respond_to[respond_dst] = {}
        for tmp_dev in tmp_respond_to[i][respond_dst]:
            if not tmp_dev in respond_to[respond_dst]:
                respond_to[respond_dst][tmp_dev] = 0
            else:
                print('Not good')
            respond_to[respond_dst][tmp_dev] += tmp_respond_to[i][respond_dst][tmp_dev]



out_file = os.path.join(output_dir,'_response_get.json')
with open(out_file, 'w') as f:
    f.write(json.dumps(response_get, indent=4))
out_file2 = os.path.join(output_dir,'_respond_to.json')
with open(out_file2, 'w') as f:
    f.write(json.dumps(respond_to, indent=4))
