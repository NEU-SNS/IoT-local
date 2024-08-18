import pandas as pd
import numpy as np 
from sklearn.cluster import DBSCAN
from sklearn.cluster import OPTICS
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from datetime import datetime
import os
import collections
import matplotlib
from statsmodels import api as sm
from scipy.fft import fft, ifft, fftfreq
from sklearn.metrics.pairwise import cosine_similarity
import sys

matplotlib.use('Agg')
matplotlib.rcParams['agg.path.chunksize'] = 10000
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

# root_feature = 'idle-2019-features/'
# root_feature = 'smart-speaker-idle-features/'
# root_feature = 'unctrl-features/'
# root_feature = 'idle-2020-features/'
# root_feature = '/home/hutr/local_output/idle-dataset-dec/flow_burst/'
root_feature = sys.argv[1]

device_names = []
lparas = []
for csv_file in os.listdir(root_feature):
    if csv_file.endswith('.csv'):
        device_name = csv_file.replace('csv', '')
        device_names.append(device_name)
        train_data_file = os.path.join(root_feature, csv_file)


        dname = csv_file[:-4]
        # lfiles.append(train_data_file)
        # ldnames.append(dname)

        lparas.append((train_data_file, dname))
        # print(dname)

lparas_sorted = sorted(lparas,key=lambda x:x[1])
for v in lparas_sorted:
    print(v[1])    


# file_path = '/home/hutr/local_output/idle-dataset-dec/periodic_detection/'
file_path = sys.argv[2]
if not os.path.exists(file_path):
    os.system('mkdir -pv %s' % file_path)

for a, b in enumerate(lparas):
    dname = lparas[a][-1]
    if os.path.isfile('%s/%s.txt' % (file_path, dname)):
        print('%s exist' % dname)
        continue
    data = pd.read_csv(lparas[a][0])
    # if dname !='echoshow5':
    #     continue
    # if os.path.isdir('%s/%s' % (file_path, dname)):
    #     continue
    print('Dname ', dname)
    header = ['timestamp', 'protocol', 'dst', 'flow_length']
    # continue
    # nums = data['flow_length'].values
    times = data['timestamp'].values
    protocols = data['highest_protocol'].values # highest_protocol or trans_protocol
    hosts = data['dst'].fillna('').values
    
    
    if len(times) <= 1:
        continue
    for i in range(len(protocols)):
        # tmp2 = protocols[i].split(';')
        if 'tcp' in protocols[i]:
            protocols[i] = 'tcp'
        elif 'udp' in protocols[i]:
            protocols[i] = 'udp'
        elif 'tls' in protocols[i]:
            protocols[i] = 'tls'
        if ';' in protocols[i]:
            tmp = protocols[i].split(';')
            protocols[i] = ' & '.join(tmp)
            # print(protocols[i])
    protocol_set = set(protocols)
    print(protocol_set)
    
    # for i in range(len(hosts)):
    #     if hosts[i] != '' and hosts[i] != None:
    #         tmp = hosts[i].split(';')
    #         hosts[i] = tmp[0]
    #     if hosts[i] == None:
    #         hosts[i] == 'non'
    #     hosts[i] = hosts[i].lower()
    #         # print(hosts[i])
    domain_set = set(hosts)
    print(domain_set)
    # continue
    # print(np.max(times))

    """
    Set Sampling Rate
    """
    sampling_rate = 1 # second
    binary = True # False
    if sampling_rate!= 1:
        times = list(map(lambda x:round(x/sampling_rate), times)) # sampling rate
    times = list(map(int,times))
    max_time = np.max(times)
    min_time = np.min(times)
    print(max_time,min_time)
    # continue
    protocols_count_9 = {}
    for i in range(len(times)):
        # if nums[i] == 9:
        if protocols[i] in protocols_count_9:
            protocols_count_9[protocols[i]] += 1
        else:
            protocols_count_9[protocols[i]] = 1
    print('protocols count:',protocols_count_9)

    
    for cur_protocol in protocol_set:
        # if cur_protocol != 'TCP':
        #     continue
        cur_domain_set = set()
        for i in range(len(times)):
            if protocols[i]== cur_protocol:
                cur_domain_set.add(hosts[i])

        # """
        # merge domain names with the same suffix
        # """

        # for i in cur_domain_set.copy():
        #     matched = 0
        #     if len(i.split('.')) >= 4:
        #         suffix = '.'.join([i.split('.')[-3], i.split('.')[-2], i.split('.')[-1]])
        #         for j in cur_domain_set.copy():
        #             if j == i or j.startswith('*'):
        #                 continue
        #             elif j.endswith(suffix):
        #                 matched = 1
                        
        #                 cur_domain_set.remove(j)
        #                 print('Remove : ',j)
        #                 print(cur_domain_set)
        #         if matched == 1:
        #             cur_domain_set.remove(i)
        #             print('Remove : ',i)
        #             cur_domain_set.add('*.'+suffix)
        

        print('Protocol %s, domain set:' % cur_protocol)
        print(cur_domain_set)
        # if cur_domain_set == set():
            # cur_domain_set.add('')
        for cur_domain in cur_domain_set:
            # if cur_domain != 'avs-alexa-3-na.amazon.com':
            #     continue
            print('Protocol %s, domain: %s' % (cur_protocol,cur_domain))

            domain_count = {}
            count_dic ={}
            cur_feature = []
            filter_feature = []
            for i in range(len(times)):
                # if cur_domain.startswith('*'):
                #     matched_suffix = hosts[i].endswith(cur_domain[2:])
                # else:
                #     matched_suffix = False
                if protocols[i]== cur_protocol and hosts[i] == cur_domain: #    and nums[i] == 4 and   ''  (max_time-43200)
                    # and hosts[i] == 'd3h5bk8iotgjvw.cloudfront.net' and hosts[i] == 'device-artifacts-v2.s3.amazonaws.com'
                    # times[i] >= min_time and times[i] <= max_time and
                    # times[i] >= min_time and times[i] <= max_time and
                    # if nums[i]==2:
                    # print(hosts[i],nums[i])
                    # print(times[i],nums[i],protocols[i])
                    if cur_domain in domain_count:
                        domain_count[cur_domain] += 1
                    else:
                        domain_count[cur_domain] = 1
                    
                    # if protocols[i]== 'GQUIC':
                    if times[i] in count_dic:
                        if binary:
                            count_dic[times[i]] += 1
                        else:
                            count_dic[times[i]] += nums[i]
                    else:
                        if binary:
                            count_dic[times[i]] = 1
                        else:
                            count_dic[times[i]] = nums[i]
                        

                    filter_feature.append(True)
                else:
                    filter_feature.append(False)
            
            
            print('Domain count flow:', domain_count)
            domain_count2 = len(count_dic.keys())

            print('Domain count unique block:', domain_count2)
            if count_dic == {} or domain_count2 <= 1:
                continue
            # if domain_count[cur_domain] <= 10:
            #     continue
            
            '''
            min time = start time
            '''
            min_time_tmp = min_time
            # min_time_tmp = np.min(list(count_dic.keys()))
            while(min_time_tmp <= max_time):
                if min_time_tmp not in count_dic:
                    count_dic[min_time_tmp] = 0
                min_time_tmp += 1 
            # tmp_min = np.min(list(count_dic.keys()))
            # tmp_max = np.max(list(count_dic.keys()))
            # print(tmp_min, tmp_max)
            # while(tmp_min<=tmp_max):
            #     tmp_min+=1 
            #     if tmp_min not in count_dic:
            #         count_dic[tmp_min] = 0

            

            # print(count_dic)

            requestOrdered = dict(collections.OrderedDict(sorted(count_dic.items(), key=lambda t: t[0])))
            x = list(requestOrdered.keys())
            x_min_tmp = x[0]
            x = list(map(lambda x:x-x_min_tmp,x))
            y = list(requestOrdered.values())

            
            # sampling_period = 600 # second, for lager sampling period
            # count = 0
            # count_new = 0
            # new_x = []
            # new_y = []
            # for i in range(len(x)):
            #     if count!= sampling_period:
            #         count += 1
            #         continue
            #     count = 0 
            #     try:
            #         new_x.append(count_new)
            #         # new_x.append(count_new+1)
            #         new_y.append(np.sum(y[count_new*sampling_period:(count_new+1)*sampling_period]))
            #         # if any(y[count_new*sampling_period:(count_new+1)*sampling_period]):
            #         #     new_y.append(1)
            #         # else:
            #         #     new_y.append(0)
            #     except:
            #         break
            #     count_new += 1
            # x = new_x
            # y = new_y
            # print(len(x), x, y)

            os.makedirs('%s/%s' % (file_path,dname), exist_ok=True)
            """
            plt.figure()
            plt.plot(x, y) #
            plt.grid()
            plt.xlabel('time')
            plt.ylabel('volume')
            plt.yscale("log")
            plt.title('%s'% (dname))
            plt.savefig('%s/%s/%s_%s.png' % (file_path,dname,cur_domain, cur_protocol))
            # plt.show()
            plt.close()
            """
            count=0
            time_list =  []
            if domain_count2 < 30:
                for i in y:
                    if i > 0:
                        print(count, i)
                        time_list.append(count)
                    count+=1

            
            # number of signal points
            # N = 800
            N = len(x) #  total number of discrete data points taken.
            print('N:', N)
            # sample spacing
            # T = 1.0 / 800.0 # total sampling time/ N
            # T = 1.0 / ( N) # time between data points
            T = N / N
            # sampling frequency 
            f_s = 1/T
            
            yf = fft(y)
            xf = fftfreq(N, T)[:N//2]
            # yf[0] is dc
            tmp_max = np.max(np.abs(yf[0:N//2]))
            tmp_mean = np.mean(np.abs(yf[0:N//2]))
            tmp_std = np.std(np.abs(yf[0:N//2]))
            print(tmp_max, tmp_mean,tmp_std)
            # print(np.abs(yf[126]))
            
            p_max_list = []
            for i in range(100):
                y_shuffle = np.random.permutation(y).tolist()
                p_max_list.append(np.max(np.abs(fft(y_shuffle)[1:N//2]).tolist()))
            threshold_99 = sorted(p_max_list)[-6]
            if sampling_rate >= 600:
                threshold_99 = sorted(p_max_list)[-11]
                print('Threshold 90 percentile: ', threshold_99)
            else:
                print('Threshold 95 percentile: ', threshold_99)
            
            
            tmp_list = []
            tmp_list_yf = []
            # if tmp_max > 3 * tmp_mean:
            for i in range(len(yf[0:N//2])):
                if i == 0 or i == 1  or i ==len(yf)-1: # or i < N/10000
                    continue
                if np.abs(yf[i]) > threshold_99:
                # if np.abs(yf[i]) > 0.1 * tmp_max and np.abs(yf[i]) > 3*tmp_std + tmp_mean and np.abs(yf[i])>np.abs(yf[i-1])and np.abs(yf[i])>np.abs(yf[i+1]):
                    tmp_list.append(i)
                    tmp_list_yf.append(np.abs(yf[i]))

            print('List len > threshold:', len(tmp_list))
            print('yf index: ', tmp_list[:10])
            print('yf: ', tmp_list_yf[:10])
            
            print('zipped:', sorted(list(zip(tmp_list,tmp_list_yf)), key = lambda x:x[1], reverse = True)[:5])
        
            period = []
            period_tmp_list = []
            if len(tmp_list) >0:
                for i in range(len(tmp_list)):
                    if sampling_rate >600 or round(N/tmp_list[i]) >= 10:
                        if len(period) == 0:
                            period.append(round(N/tmp_list[i]))
                            period_tmp_list.append(tmp_list[i])
                        else:
                            if round(N/tmp_list[i]) != period[-1]:
                                period.append(round(N/tmp_list[i]))
                                period_tmp_list.append(tmp_list[i])
            
            print('Protocol %s, domain: %s' % (cur_protocol,cur_domain))
            print('period:',period[:])
            #             if len(tmp_list) >0:
            #                 print(tmp_list[np.argmax(tmp_list_yf[:N//2])])
            #                 period_tmp2 = round(N/tmp_list[np.argmax(tmp_list_yf[:N//2])])
            #                 print(period_tmp2)
            #                 print(np.correlate(y,np.concatenate((y[period_tmp2:],y[:period_tmp2]))).tolist()[0])
            
    
            acf = sm.tsa.acf(y, nlags=len(y),fft=True)
        
            autocorrelation = []
            if len(period) == 0:
                pass
                # period.append(60)
            else:
                for i in range(len(period)):
                    tmp_range = [max(round(N/(period_tmp_list[i]-1)),period[i]+1), min(round(N/(period_tmp_list[i]+1)),period[i]-1)]
                    # tmp_range = [period[i]+1, period[i]-1]
                    # print(tmp_range)
                    #   cur_auto = []
                    j = tmp_range[0]
                    while (j >= tmp_range[1]):
                        if j >= len(acf):
                            break
                        auto_tmp = acf[j]
                        # auto_tmp = np.correlate(y,np.concatenate((y[j:],y[:j]))).tolist()[0]
                        if auto_tmp >= 3.315/np.sqrt(N):
                            autocorrelation.append(((j,auto_tmp))) # '%d:%d ' % 
                        j-=1
                    # cur_auto.append(np.correlate(y,np.concatenate((y[period[i]-1:],y[:period[i]-1]))).tolist()[0])
                    # cur_auto.append(np.correlate(y,np.concatenate((y[period[i]:],y[:period[i]]))).tolist()[0])
                    # cur_auto.append(np.correlate(y,np.concatenate((y[period[i]+1:],y[:period[i]+1]))).tolist()[0])
                    # autocorrelation.append(cur_auto)
                autocorrelation = set(autocorrelation)
                autocorrelation = sorted(autocorrelation,key=lambda x:x[1], reverse = True)
                if len(autocorrelation) > 20:
                    print('## Autocorrelation ',autocorrelation[:20])
                else:
                    print('## Autocorrelation ',autocorrelation)
                # print("# Auto 30: ", acf[29], acf[30], acf[31])
            if not any(autocorrelation) and domain_count2 <= 6 and domain_count2 >= 4:
                # autocorrelation = []
                time_diff = [abs(time_list[i + 1] - time_list[i]) for i in range(len(time_list)-1)]

                diff_diff = [abs(time_diff[i + 1] - time_diff[i]) for i in range(len(time_diff)-1)]
                res = [x for x in diff_diff if x <= 3600/sampling_rate]
                if len(res)==len(diff_diff):
                    autocorrelation.append((np.mean(time_diff),0))
                    print('## Less than 6: period ',autocorrelation)
                # print(time_diff)

            plt.figure()
            plt.plot(xf, 1.0/N * np.abs(yf[0:N//2]))
            plt.grid()
            plt.savefig('%s/%s/%s_%s_fft.png' % (file_path,dname,cur_domain, cur_protocol))
            plt.close()
            # plt.show() # fourier plt
            # lag = np.arange(len(y))
            # # plt.figure()
            # # plt.plot(lag,acf)
            # # if np.argmax(acf[1:])+1 > 2500:
            # #     xrange = np.argmax(acf[1:])+100
            # # else:
            # #     xrange = 2500
            # # plt.xlim((0, xrange))
            # # plt.grid()
            # # plt.show() # autocorr plt
            # acf_burst = [] 
            # print('acf average, max', np.mean(acf[1:]), np.std(acf[1:]), np.max(acf[1:]), np.argmax(acf[1:])+1)
            # # p_list = []
            # for i in range(len(acf)):
            #     if acf[i] >= 3.315/np.sqrt(N):
            #         acf_burst.append(i)
            #         # p_list.append(p[i])
            # print('### Autocorrelation2 ',acf_burst[:10])

            print('--------------------------------------------------------')

            with open('%s/%s.txt' % (file_path,dname), 'a+') as file:
                    if len(period) > 0 and any(autocorrelation): # and len(acf_burst) > 1
                        file.write('\n%s %s # %d: ' %(cur_protocol,cur_domain,domain_count[cur_domain]))
                        # file.write(' '.join(str(item) for item in period))
                        # file.write(', autocor:')
                        # for i in range(len(autocorrelation)):
                        #     file.write(' %d' % autocorrelation[i])
                        # file.write(', autocors:')
                        # for i in range(len(acf_burst[:5])):
                        #     file.write(' %d' % acf_burst[i])
                        file.write(' best: %d'% (list(autocorrelation)[0][0]  ))
                        if len(list(autocorrelation)) > 1:
                            file.write(', %d'% (list(autocorrelation)[1][0]  ))
                        
                
                    else:
                        file.write('\nNo period detected %s %s # %d ' %(cur_protocol,cur_domain, domain_count[cur_domain])) 
    
