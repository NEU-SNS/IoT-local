import pyshark
import re
from pathlib import Path
import os
import sys
# import nest_asyncio
# nest_asyncio.apply()

total_certs = 0
#device_count = {}

class TLSCert:
    def __init__(self):
        self.issuer = []
        self.subject = []

    def add_issuer_sequence(self, seq):
        self.issuer.append(seq)

    def add_subject_sequence(self, seq):
        self.subject.append(seq)

    def __str__(self):
        return "\tIssuer: " + str(self.issuer) + "\n\tSubject: " + str(self.subject)


def get_all(field_container):
    field_container: LayerFieldsContainer
    field_container = field_container.all_fields
    tmp = []
    # field: LayerField
    for field in field_container:
        tmp.append(field.get_default_value())
    return tmp

# tls.handshake.extensions_server_name

def extract_certs(tls_layer):
    """ extract certs from a packet's tls layer

    Args:
        tls_layer (_type_): tls layer data of a packet

    Returns:
        _type_: certs 
    """
    cert_count = 0
    if_rdnSequence_count = []
    af_rdnSequence_count = []
    rdn = []
    field_container: LayerFieldsContainer
    a = list(tls_layer._all_fields.values())
    for field_container in a:
        # field: LayerField
        field = field_container.main_field

        if field.name == 'x509if.RelativeDistinguishedName_item_element':
            rdn = (get_all(field_container))
        elif field.name == 'x509af.signedCertificate_element':
            cert_count = len(field_container.all_fields)
        elif field.name == 'x509if.rdnSequence':
            if_rdnSequence_count = get_all(field_container)
        elif field.name == 'x509af.rdnSequence':
            af_rdnSequence_count = get_all(field_container)

    certs = []
    for i in range(cert_count):
        cert = TLSCert()
        for j in range(int(if_rdnSequence_count[i])):
            cert.add_issuer_sequence(rdn.pop(0))
        for j in range(int(af_rdnSequence_count[i])):
            cert.add_subject_sequence(rdn.pop(0))
        certs.append(cert)

    return certs

def analyzePacket(packet, ca_count, common_name_set):
    global total_certs
    # packet: Packet
    # layer: Layer
    layer = packet.tls
    cert_list = extract_certs(layer)
    for cert in cert_list:  # cert class
        total_certs += 1
        result = re.search('id-at-commonName=[^\)]*', str(cert.issuer))
        common_name = re.search('id-at-commonName=[^\)]*', str(cert.subject))
        if common_name is not None:
            common_name_str = str(common_name.group(0)[17:])
            # print(common_name_str)
        else:
            common_name_str = 'n/a'
        if result is not None:
            ca_name = result.group(0)[17:]
            # print(ca_name, ', ', common_name_str)
            ca_count[ca_name] = ca_count.get(ca_name, 0) + 1
            if ca_name not in common_name_set:
                common_name_set[ca_name] = set([common_name_str])
            else:
                common_name_set[ca_name].add(common_name_str)


    

    return ca_count, common_name_set

def main():
    # directory = '/home/hutr/2022-datasets/idle-dataset'
    directory = sys.argv[1]
    out_file = sys.argv[2]
    # = '/home/hutr/2022-datasets/idle-dataset-nov'
    # directory = '/home/hutr/2022-datasets/tagged-local'

    for device in os.listdir(directory):

        device_folder = os.path.join(directory, device)

        if os.path.isfile(device_folder):
            print(device_folder)
            exit(1)
        # Getting the device name from MAC address(folder name)
        # devices = open("devices.txt", "r")
        # for line in devices:
        #     if devicemac in line:
        #         devicename = line.split(' ')[1].rstrip()
        #         print('\n##########')
        #         print(devicename)
        #         print('##########\n')
        # devices.close()

        device_count = {}
        ca_count = {}
        common_name_set = {}
        # files = []
        for cur_file in os.listdir(device_folder):
            cur_file = os.path.join(device_folder, cur_file)
            if os.path.isfile(cur_file) and not cur_file.endswith('.pcap'):
                print(cur_file)
                continue 
            elif os.path.isdir(cur_file):
                for cur_cur_file in os.listdir(cur_file):
                    cur_cur_file = os.path.join(cur_file, cur_cur_file)
                    try:
                        capture = pyshark.FileCapture(str(cur_cur_file), display_filter='tls.handshake.certificate')
                        count = 0
                        for packet in capture:
                            ca_count, common_name_set = analyzePacket(packet, ca_count, common_name_set)
                            print('!!!Packet: ', ca_count, common_name_set)
                            count += 1
                        print('%s, %s: %d' %(device, os.path.basename(cur_file), count))
                        capture.close()
                    except Exception as e:
                        print("SKIP", e)
                continue
            
            # try:
            capture = pyshark.FileCapture(str(cur_file), display_filter='tls.handshake.certificate')
            count = 0
            for packet in capture:
                ca_count, common_name_set = analyzePacket(packet, ca_count, common_name_set)
                count += 1
            print('%s: %d' %(device, count))
            capture.close()
            # except Exception as e:
            #     print("SKIP", e)

        device_count[device] = [ca_count, common_name_set]

        with open(out_file, 'a') as f:
            for device in device_count:
                f.write('----------\n')
                f.write(device)
                f.write('\n----------\n') 
                for key in device_count[device][0]:  
                    f.write('%s -> %s , common name: %s\n' % (key, device_count[device][0][key], ' '.join(list(device_count[device][1][key]))))

if __name__ == "__main__":
    main()