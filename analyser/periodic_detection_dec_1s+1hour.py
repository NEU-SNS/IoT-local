import os
import re
device_names = []
dirc = './freq_period_new/2020_Dec_1s/'
dirc2 = './freq_period_new/2020_Dec_1hour/'
# dirc = './freq_period_new/2019_Apr_final_new_all/'
# out_dir = './freq_period_new/2019_Apr_fingerprint_all/'
# dirc = './freq_period_new/2019_Apr_uk/'
# out_dir = './freq_period_new/2019_Apr_uk_fingerprint/'
# dirc = './freq_period_new/smart-speaker/'
out_dir = './freq_period_new/2020_Dec_fingerprint_new/'
for file in os.listdir(dirc):  #  /freq_new/
        if file.endswith('.txt'):
            device_name = file.replace('.txt', '')
            device_names.append(device_name)
            
            print(device_name)

            f = open(dirc+file) # './freq_new/'+
            f2 = open(dirc2+file) 

            out_file = open(out_dir+file,'a+')
            non_nums = 0
            is_nums = 0
            total_number = 0

            output_dic = {}
            for line in f:
                if line=='\n':
                    continue

                total_number += int(re.findall(r'# \d+', line)[0].split()[-1])
                if line.startswith('No'): #   
                    continue
                    # if (line.split()[3] != 'DNS' and line.split()[3] != 'DHCP' and line.split()[3] != 'NTP' and line.split()[3] != 'MDNS'  and line.split()[3] != 'SSDP'):
                    #     # print([int(s) for s in line.split() if s.isdigit()])
                    #     # print(re.findall(r'# \d+', line))
                    #     non_nums += int(re.findall(r'# \d+', line)[0].split()[-1])
                    # else:
                    #     is_nums += int(re.findall(r'# \d+', line)[0].split()[-1])
                elif line!='\n': 
                    # print(re.findall(r'# \d+', line))
                    is_nums += int(re.findall(r'# \d+', line)[0].split()[-1])

                    protocol = line.split()[0]
                    domain_name = line.split()[1]
                    tmp_period = int(line.split()[-1])

                    # print(protocol, domain_name, tmp_period)
                    output_dic[(protocol, domain_name)] = [tmp_period]
                    # out_file.write('%s %s %d \n' %(protocol, domain_name, tmp_period))


            for line in f2:
                if line=='\n':
                    continue

                if line.startswith('No'): #   or line.startswith('Unsure')
                    protocol = line.split()[3]
                    domain_name = line.split()[4]
                    if (protocol,domain_name) in output_dic:
                        continue
                    else:
                        if (line.split()[3] != 'DNS' and line.split()[3] != 'DHCP' and line.split()[3] != 'NTP' and line.split()[3] != 'MDNS'  and line.split()[3] != 'SSDP'):
                            # print([int(s) for s in line.split() if s.isdigit()])
                            # print(re.findall(r'# \d+', line))
                            non_nums += int(re.findall(r'# \d+', line)[0].split()[-1])
                        else:
                            is_nums += int(re.findall(r'# \d+', line)[0].split()[-1])

                elif line!='\n': 
                    # print(re.findall(r'# \d+', line))
                    

                    protocol = line.split()[0]
                    domain_name = line.split()[1]
                    tmp_period = int(line.split()[-1])*3600
                    if (protocol,domain_name) in output_dic:
                        output_dic[(protocol, domain_name)].append( tmp_period )
                    else:
                        output_dic[(protocol, domain_name)] = [tmp_period]
                        is_nums += int(re.findall(r'# \d+', line)[0].split()[-1])

                    # print(protocol, domain_name, tmp_period)
                    # out_file.write('%s %s %d \n' %(protocol, domain_name, tmp_period))
            
            for key in output_dic.keys():
                if len(output_dic[key]) == 1:
                    tmp_period = output_dic[key][0]
                    out_file.write('%s %s %d \n' %(key[0], key[1], tmp_period))
                else:
                    out_file.write('%s %s %d %d \n' %(key[0], key[1], output_dic[key][0], output_dic[key][1]))
                
            print('non-period: ',non_nums)
            print('period or DNS/NTP/DHCP: ',is_nums)
            print('total: ',total_number)
            print('')
