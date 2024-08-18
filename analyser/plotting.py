import matplotlib
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
from collections import Counter
from copy import deepcopy
import os
import sys
import numpy as np
matplotlib.use('Agg')
import warnings
warnings.filterwarnings("ignore")

def plotting_bar(input_dict, output_dir, title):
    if not os.path.exists(os.path.dirname(output_dir)):
        os.system('mkdir -pv %s' % os.path.dirname(output_dir))
    len_input_dict = len(input_dict.keys())
    if len_input_dict==0:
        return 0
    elif len_input_dict>30:
        fig = plt.subplots(figsize=(22.5, 10.5), dpi=150)
        # fig.set_dpi(150)
    else:
        fig = plt.subplots()
    input_dict = sorted(input_dict.items(), key=lambda t: t[1])
    xs = [x[0] for x in input_dict]
    values = [x[1] for x in input_dict]
    # print(xs,values)
    if len(values)==0:
        return 0
    plt.bar(xs, values)
    
    ax = plt.gca()
    if len_input_dict>15:
        ax.set_xticklabels(xs,rotation=90) # ha="right"
    else:
        ax.set_xticklabels(xs) # ha="right"
    if max(values) > 1000:
        ax.set_yscale('log')
    # plt.xlabel("Devices")
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    # plt.ylabel("No. of students enrolled")
    plt.title("%s" % title)
    ax.set_axisbelow(True)
    ax.grid(axis='y', linestyle='dashed')
    
    # plt.legend((p1[0], p2[0], p3[0]), ('uni', 'multi', 'broadcast'))
    # dic = output_dir + '/'+ os.path.basename(output_dir) + '.pdf'
    dic = output_dir + '.pdf'
    plt.savefig(dic)
    # dic = output_dir + '.svg'
    # plt.savefig(dic)
    return 0

def plotting_mean_bar(input_dict, output_dir, title):
    if not os.path.exists(os.path.dirname(output_dir)):
        os.system('mkdir -pv %s' % os.path.dirname(output_dir))
    if len(input_dict.keys())==0:
        return 0
    length = len(input_dict.keys())
    mean = [np.mean(x) for x in input_dict.values()]
    std = [np.std(x) for x in input_dict.values()]

    zipped = list(zip(*list(sorted(zip(input_dict.keys(), mean, std), key=lambda t: t[1]))))
    keys = list(zipped[0])
    mean = list(zipped[1])
    std = list(zipped[2])
    if len(keys)==0:
        return 0

    fig, ax = plt.subplots()
    ax.bar(keys, mean, yerr=std, ecolor='black') # , capsize=10 # align='center', alpha=0.5, 
    ax.set_ylabel('average flow size')
    ax.set_xticks(keys)
    # ax.set_xticklabels(keys)
    ax.set_xticklabels(keys,rotation=90)
    if max(mean) > 1000:
        ax.set_yscale('log')
    ax.set_title('%s' % title)
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    # dic = output_dir + '/'+ os.path.basename(output_dir) + '.pdf'
    dic = output_dir + '.pdf'
    plt.savefig(dic)

    return 0

def plotting_multicolumn_bar(input_dict, output_dir, title):
    if not os.path.exists(os.path.dirname(output_dir)):
        os.system('mkdir -pv %s' % os.path.dirname(output_dir))
    if len(input_dict.keys())==0:
        return 0
    if len(input_dict.keys())>30:
        fig = plt.subplots(figsize=(22.5, 10.5), dpi=150)
        # fig.set_size_inches(22.5, 10.5)
        # fig.set_dpi(150)
    else:
        fig = plt.subplots()

    x_axis = np.arange(len(input_dict.keys()))
    

    input_dict = sorted(input_dict.items(), key=lambda t: (t[1][0]+t[1][1]+t[1][2]))
    # print(input_dict)
    xs = [x[0] for x in input_dict]
    values = np.asarray([x[1] for x in input_dict])
    if len(values)==0:
        return 0
    # values = np.asarray(list(input_dict.values()))
    v1 = values[:,0]
    v2 = values[:,1]
    v3 = values[:,2]
    # p1 = plt.bar(xs, v1)
    # p2 = plt.bar(xs, v2, bottom=v1)
    # p3 = plt.bar(xs, v3, bottom=v1+v2)
    # # plt.bar(xs, values)
    
    p1 = plt.bar(x_axis +0.20, v1, width=0.2, label = 'Unicast')
    p2 = plt.bar(x_axis +0.20*2, v2, width=0.2, label = 'Multicast')
    p3 = plt.bar(x_axis +0.20*3, v3, width=0.2, label = 'Broadcast')

    # Xticks

    plt.xticks(x_axis,xs)

    
    ax = plt.gca()
    ax.set_xticklabels(xs,rotation=90)
    # ax.set_yscale('log')
    plt.yscale('log')
    # plt.xlabel("Devices")
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    # plt.ylabel("No. of students enrolled")
    plt.title("%s" % title)
    plt.legend((p1[0], p2[0], p3[0]), ('uni', 'multi', 'broadcast'))
    # dic = output_dir + '/'+ os.path.basename(output_dir) + '.pdf'
    dic = output_dir + '.pdf'
    plt.savefig(dic)

    return 0 

    
def plotting_stacked_bar(input_dict, output_dir, title):
    if not os.path.exists(os.path.dirname(output_dir)):
        os.system('mkdir -pv %s' % os.path.dirname(output_dir))
    if len(input_dict.keys())==0:
        return 0
    
    if len(input_dict.keys())>30:
        fig = plt.subplots(figsize=(22.5, 10.5), dpi=150)
        # fig.set_size_inches(22.5, 10.5)
        # fig.set_dpi(150)
    else:
        fig = plt.subplots()
    
    input_dict = sorted(input_dict.items(), key=lambda t: (t[1][0]+t[1][1]+t[1][2]))
    # print(input_dict)
    xs = [x[0] for x in input_dict]
    values = np.asarray([x[1] for x in input_dict])
    # values = np.asarray(list(input_dict.values()))
    v1 = values[:,0]
    v2 = values[:,1]
    v3 = values[:,2]
    p1 = plt.bar(xs, v1)
    p2 = plt.bar(xs, v2, bottom=v1)
    p3 = plt.bar(xs, v3, bottom=v1+v2)
    # plt.bar(xs, values)
    # 
    ax = plt.gca()
    ax.set_xticklabels(xs,rotation=90)
    # plt.xlabel("Devices")
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    # plt.ylabel("No. of students enrolled")
    plt.title("%s" % title)
    plt.legend((p1[0], p2[0], p3[0]), ('uni', 'multi', 'broadcast'))
    # dic = output_dir + '/'+ os.path.basename(output_dir) + '.pdf'
    dic = output_dir + '.pdf'
    plt.savefig(dic)
    return 0


# TODO 
def plotting_cdf():
    # return 0
    print('ploting ',dev_name)
    diff = result[:, 2]
    diff = diff.astype(np.float)
    ts  = result[:, 1]
    
    
    count_dic = {}
    plt.figure()
    requestOrdered = dict(collections.OrderedDict(sorted(count_dic.items(), key=lambda t: t[0])))
    x = list(requestOrdered.keys())
    y = list(requestOrdered.values())
    y = np.cumsum(y)
    plt.plot(x, y)
    # formatter = FuncFormatter(to_percent)
    plt.gca().yaxis.set_major_formatter(PercentFormatter(xmax=len(result)))
    # urllength += len(test[i].urls)
    # plt.yscale('log')
    # plt.xscale('log')
    plt.grid()
    plt.xlabel('time intervel')
    plt.ylabel('count')
    plt.title('%s'%dev_name)
    dic = './cdf/time_interval_idle_%s.png' % dev_name
    plt.savefig(dic)

    protocols = result[:,4]
    count_dic = Counter(protocols)
    fig, ax = plt.subplots()
    print(count_dic)
    # add a 'best fit' line
    x = list(count_dic.keys())
    y = list(count_dic.values())
    ax.bar(x, y)
    # ax.set_xticks(rotation=90)
    ax.set_xticklabels(x,rotation=90)
    for i, v in enumerate(y):
        ax.text(i-0.5,v + 5, str(v), color='blue')
    plt.xlabel('protocol')
    plt.ylabel('Count')
    plt.title('Protocols Histogram')

    # Tweak spacing to prevent clipping of ylabel

    dic = './cdf/hist_%s.png' % dev_name
    plt.savefig(dic)

    return 0
