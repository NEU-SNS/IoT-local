import os
import sys


print('Running...', sys.argv[0])
in_dir = sys.argv[1]
out_dir = sys.argv[2]
print('Input dir: ', in_dir)
print('Output dir:', out_dir)


device_to_android = {}
device_to_iphone = {}
for device_file in os.listdir(in_dir):
    if not device_file.endswith('.txt'):
        continue
    device_name = device_file.split('.')[0]
    with open(os.path.join(in_dir, device_file), 'r') as f:
        for line in f: 
            if 'pixel' in line: 
                # android phone
                device_to_android[device_name] = device_to_android.get(device_name, [])
                device_to_android[device_name].append(line.strip())
            elif 'iphone' in line:
                # iphone
                device_to_iphone[device_name] = device_to_iphone.get(device_name, [])
                device_to_iphone[device_name].append(line.strip())

if not os.path.exists(out_dir):
    os.system('mkdir -pv %s' % out_dir)
with open(os.path.join(out_dir, 'device_to_phone.txt'), 'w+') as f:
    f.write('Device to Android phone: \n')
    for k, v in device_to_android.items():
        f.write('%s: %s\n' % (k,' '.join(v)))
    f.write('Device to IOS phone: \n')
    for k, v in device_to_iphone.items():
        f.write('%s: %s\n' % (k,' '.join(v)))