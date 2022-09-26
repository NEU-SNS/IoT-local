import os


def main():
    all_counts = {}
    for protocol in ['tcp', 'udp']:
        for src_file in os.listdir(f'/home/hutr/local_output/idle-dataset/{protocol}_output/'):
            src_device = src_file[:-4]
            with open(f'/home/hutr/local_output/idle-dataset/{protocol}_output/' + src_file) as count:
                for line in count.readlines():
                    if len(line) <= 1:
                        continue
                    dst_device = line.strip().split(' ')[0]
                    dst_volume = int(line.strip().split(' ')[1])
                    if (dst_device, src_device) in all_counts:
                        src_volume = all_counts[(dst_device, src_device)]
                        if src_volume != dst_volume:
                            print('Disparity found:')
                            print(f' - {src_device} sent {dst_volume} {protocol.swapcase()} packets to {dst_device}')
                            print(f' - {dst_device} sent {src_volume} {protocol.swapcase()} packets to {src_device}')
                    else:
                        all_counts[(src_device, dst_device)] = dst_volume


if __name__ == "__main__":
    main()

