import math 
import os
import sys
import typing
from sklearn import preprocessing
import numpy as np 
# import constants as c
min_max_scaler = preprocessing.MinMaxScaler((0,10))

def print_usage(is_error):
    # TODO
    print('visualization of local communication')
    return


def example():
    # nodes = new vis.DataSet([{"id": "echoshow5", "label": "echoshow5", "shape": "dot", "size": 8}, {"id": "t-philips-hub", "label": "t-philips-hub", "shape": "dot", "size": 8}, {"id": "echodot4b", "label": "echodot4b", "shape": "dot", "size": 8}, {"id": "echospot", "label": "echospot", "shape": "dot", "size": 8}, {"id": "anpviz-cam", "label": "anpviz-cam", "shape": "dot", "size": 8}, {"id": "t-wemo-plug", "label": "t-wemo-plug", "shape": "dot", "size": 8}, {"id": "amcrest-cam-wired", "label": "amcrest-cam-wired", "shape": "dot", "size": 8}, {"id": "wansview-cam-wired", "label": "wansview-cam-wired", "shape": "dot", "size": 8}, {"id": "chromecast-googletv", "label": "chromecast-googletv", "shape": "dot", "size": 8}, {"id": "google-home-mini", "label": "google-home-mini", "shape": "dot", "size": 8}, {"id": "google-nest-mini2", "label": "google-nest-mini2", "shape": "dot", "size": 8}, {"id": "google-home-mini3", "label": "google-home-mini3", "shape": "dot", "size": 8}, {"id": "google-home-mini2", "label": "google-home-mini2", "shape": "dot", "size": 8}, {"id": "google-nest-mini1", "label": "google-nest-mini1", "shape": "dot", "size": 8}]);
    # edges = new vis.DataSet([{"from": "echoshow5", "to": "t-philips-hub", "value": 10.0}, {"from": "echodot4b", "to": "t-philips-hub", "value": 8.188531921359715}, {"from": "echospot", "to": "t-philips-hub", "value": 1.28914278736605}, {"from": "anpviz-cam", "to": "t-philips-hub", "value": 0.1030366515047479}, {"from": "echodot4b", "to": "t-wemo-plug", "value": 2.0485676520319145}, {"from": "amcrest-cam-wired", "to": "echodot4b", "value": 0.13049532225266353}, {"from": "echodot4b", "to": "wansview-cam-wired", "value": 0.15851442052932607}, {"from": "chromecast-googletv", "to": "echodot4b", "value": 0.014899170886199952}, {"from": "echoshow5", "to": "t-wemo-plug", "value": 2.5432656886674723}, {"from": "amcrest-cam-wired", "to": "echoshow5", "value": 0.15979019051346552}, {"from": "echoshow5", "to": "wansview-cam-wired", "value": 0.19409929044407276}, {"from": "chromecast-googletv", "to": "echoshow5", "value": 0.020858839240679928}, {"from": "google-home-mini", "to": "google-nest-mini2", "value": 3.1653493582193533}, {"from": "google-home-mini", "to": "google-home-mini3", "value": 5.449610958499658}, {"from": "echospot", "to": "t-wemo-plug", "value": 2.4822246512477713}, {"from": "echospot", "to": "wansview-cam-wired", "value": 0.19086430227000487}, {"from": "anpviz-cam", "to": "wansview-cam-wired", "value": 0.003296498512588888}, {"from": "google-home-mini2", "to": "google-nest-mini1", "value": 3.7885607173107863}, {"from": "amcrest-cam-wired", "to": "echospot", "value": 0.15712702067157444}, {"from": "chromecast-googletv", "to": "echospot", "value": 0.026818507595159913}])
    return 0

def output_data(out_file:str, dict_dec:dict[str, dict[str, int]]) -> bool: 
    # print('output:', out_file, dict_dec)
    # 
    with open(out_file, 'w') as of:
        # write nodes: 
        of.write('nodes = new vis.DataSet([')
        for i in range(len(dict_dec)):
            dev = list(dict_dec.keys())[i]
            of.write('{"id": "%s", "label": "%s", "shape": "dot", "size": 8}' % (dev,dev))
            if i != len(dict_dec)-1:
                of.write(', ')
            else:
                of.write(']);')
        of.write('\n\n')

        # write edges:
        of.write('edges = new vis.DataSet([')
        for i in range(len(dict_dec)):
            dev = list(dict_dec.keys())[i]
            dst_list = dict_dec[dev]
            if len(dst_list) == 0:
                continue
            
            for j in range(len(dst_list)): 
                dst_device = list(dst_list.keys())[j]
                dst_voulme = dst_list[dst_device]

                of.write('{"from": "%s", "to": "%s", "value": %f}' % (dev, dst_device, min_max_scaler.transform(np.array([float(dst_voulme)]).reshape(1, -1))))
                if i != len(dict_dec)-1 or j != len(dst_list)-1:
                    of.write(', ')
                else:
                    of.write(']);')
        

    return 0 

def main():
    [ print_usage(0) for arg in sys.argv if arg in ("-h", "--help") ]

    print("Running %s..." % sys.argv[0])

    in_dir = sys.argv[1]
    out_dir = sys.argv[2]

    dict_dec = {}
    volume_standardization = []
    count = set()
    for dev_file in os.listdir(in_dir):
        if dev_file.startswith(".") or dev_file.startswith("log"):
            continue
        
        # output_file = os.path.join(out_dir, dev_dir + '.csv') # Output file
        if not dev_file.endswith(".txt"):
            # print(c.WRONG_EXT % ("input file", "txt", full_dec_file), file=sys.stderr)
            continue
        
        device = dev_file.split('.')[0]
        # if device != 'amazon-plug':
        #     continue
        if device not in dict_dec:
            dict_dec[device] = {}

        dev_file_full =  os.path.join(in_dir, dev_file)
        with open(dev_file_full, 'r') as ff:
            lines = ff.readlines()
            for line in lines:
                if len(line) <= 1:
                    continue
                count.add(device)
                dst_device = line.strip().split(' ')[0]
                dst_volume = int(line.strip().split(' ')[1])
                volume_standardization.append(dst_volume)
                if line.strip() == '':
                    continue
                if dst_device in dict_dec and device in dict_dec[dst_device]:
                    dict_dec[dst_device][device] += dst_volume
                else:
                    if dst_device not in dict_dec[device]:
                        dict_dec[device][dst_device] = dst_volume
                    else:
                        dict_dec[device][dst_device] += dst_volume
    print('Count non-empty files:', len(count))
    print(count)

    volume_standardization = np.asarray(volume_standardization).reshape(-1, 1)
    min_max_scaler.fit(volume_standardization)
    if in_dir.endswith('/'):
        in_dir = in_dir[:-1]
    out_file = os.path.join(out_dir, os.path.basename(in_dir) + '.txt')
    output_data(out_file, dict_dec) # 

if __name__ == "__main__":
    main()