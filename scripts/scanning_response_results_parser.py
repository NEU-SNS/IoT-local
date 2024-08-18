import os
import sys
import csv

# Set the path to the folder of CSV files
csv_folder_path = sys.argv[1]

# Initialize a counter for the number of files that are being deleted
num_files_deleted = 0

num_files_has_non_functional_traffic = {}
responded_device_non_functional_traffic = {}
# Loop through each file in the CSV folder
for csv_file_name in os.listdir(csv_folder_path):
    # Check if the file is a CSV file
    if csv_file_name.endswith(".csv"):
        # Open the file and create a CSV reader
        device_name = csv_file_name.split('.')[0]
        with open(os.path.join(csv_folder_path, csv_file_name), "r") as csv_file:
            csv_reader = csv.reader(csv_file)
            count = 0
            for row in csv_reader:
                if count==0:
                    count+=1
                    continue
                if row[0] in ['arp', 'basicxid', 'llc', 'dhcp', 'dhcpv6', 'icmp', 'icmpv6', 'igmp', 'igmpv2', 'igmpv3']:
                    continue
                if device_name not in num_files_has_non_functional_traffic:
                    num_files_has_non_functional_traffic[device_name] = set()
                    responded_device_non_functional_traffic[device_name] = set()
                num_files_has_non_functional_traffic[device_name].add(row[0])
                responded_device_non_functional_traffic[device_name].add(row[3])
                # print(row)
            
count = 0 
sorted_num_files_has_non_functional_traffic = dict(sorted(num_files_has_non_functional_traffic.items(), key=lambda x: len(x[1]), reverse=True))
for k, v in sorted_num_files_has_non_functional_traffic.items():
    if len(v)==0:
        continue
    count+=1
    print(f"{k}: {len(v)}: {v}")
print('Count:',count)    

count = 0 
sorted_responded_device_non_functional_traffic = dict(sorted(responded_device_non_functional_traffic.items(), key=lambda x: len(x[1]), reverse=True))
for k, v in sorted_responded_device_non_functional_traffic.items():
    if len(v)==0:
        continue
    count+=1
    print(f"{k}: {len(v)}: {v}")
print('Count:',count)   

# the list of protocol got a response per device. And the number of devices repond to each discovery protocols per device



            # Count the number of lines in the file
#             num_lines = sum(1 for row in csv_reader)
#             # If the file only contains one line (the header), delete the file
#             if num_lines == 1:
#                 os.remove(os.path.join(csv_folder_path, csv_file_name))
#                 num_files_deleted += 1

# # Print the number of files that were deleted
# print(f"{num_files_deleted} file(s) were deleted.")

# ---------------------------------------------------------------
# import json

# # Open the JSON file
# # /home/hutr/local_output/idle-dataset-dec-new/scanning_response/_respond_to.json
# with open('/home/hutr/local_output/idle-dataset-dec-new/scanning_response/_response_get.json', 'r') as f:
#     data = json.load(f)


# # Create a list of tuples containing the key and the length of the corresponding value
# value_lengths = [(key, len(value)) for key, value in data.items() if isinstance(value, dict)]

# # Sort the list by the length of the values
# value_lengths.sort(key=lambda x: x[1])

# # Loop through the sorted list and print the results
# for key, value_length in value_lengths:
#     print(f"The length of {key} is {value_length}")
    
# ---------------------------------------------------------------
# import json

# # Open the JSON file
# # /home/hutr/local_output/idle-dataset-dec-new/scanning_response/_respond_to.json
# with open('/home/hutr/local_output/idle-dataset-dec-new/scanning_response_2/_response_get.json', 'r') as f:
#     data = json.load(f)

# value_sumup = []
# # Loop through each key-value pair in the dictionary
# for key, value in data.items():
#     # Check if the value is a dictionary
#     if isinstance(value, dict):
#         # Sum up the values in the dictionary
#         value_sum = sum(value.values())
#         value_sumup.append((key,value_sum))
#         # print(f"The sum of {key} is {value_sum}")
# value_sumup.sort(key=lambda x: x[1])
# # Loop through the sorted list and print the results
# count = 0
# for key, sumup in value_sumup:
#     if sumup!= 0:
#         count += 1
#     print(f"The length of {key} is {sumup}")
# print('Count non-zero:', count)