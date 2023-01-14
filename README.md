# About
This repository includes scripts to analyze local traffic of smart home IoT devices.  

# Files

- `devices.txt`: a list of all devices with their MAC addresses. Add *router* manually. 
- `analysis.py`: the main script to call.
- `analyser`: analysis files 
    - `protocols_analysis.py`: protocl-wise analysis
    - `plotting.py`: plots charts.
    - `extract_ca.py`: extracts certificates from TLS traffic. 
    - `flow_extraction_new.py`: extract flows from traffic
    - `utils.py`, `constants.py`: auxiliary files.
    - `periodic_analysis.py`: peroidicity analysis
    - `periodic_detection_dec_1s+1hour.py`: peroidicity post-analysis 
    - `protocol_identification.py`: automatically identify top-layer protocols from pcaps.
    - `all_device_analysis.py`: protocol distribution, basic analysis, plotting, etc. 
    - `protocols`: !TODO
    - `backups.py`, `flow_extraction.py`: backup file. 
    - `vis.py`: graph visualization helper. 
- `helper`: helpers
    - `setup-log.py`: get device-ip mapping from DHCP logs
- `connectedGraph`: 
    - `graph_generator.py`: generates connected graph visualizations. 
- `logs`: nohup log files. To remove
- `vis`: html graph visualizations. 
- `outputs`: extracted certificates. Need to rename this folder. 

# Usage

### `analysis`: pyshark based protocol statistic, basic analysis (plotting distribution)
python3 analysis.py ~/2022-datasets/idle-dataset ~/local_output/idle-dataset/ -b


### tshark based protocol statistic and log parsing of pyshark based protocol statistic
<!-- python3 protocol_statistics.py ~/2022-datasets/idle-dataset-dec ~/local_output/idle-dataset-dec/ -->
python3 protocol_statistics.py ~/2022-datasets/idle-dataset-dec ~/local_output/idle-dataset-dec/ -plot _overall_manual_processed.txt


### protocol-wise analysis
python3 -u analysis.py ~/2022-datasets/idle-dataset-dec ~/local_output/idle-dataset-dec/ -f PROTOCOL

### generate connected graph
python3 connectedGraph/graph_generator.py ~/local_output/idle-dataset-dec/udp_output vis
python3 connectedGraph/graph_generator.py ~/local_output/idle-dataset-dec/udp_output vis

### parse protocol logs
python3 analyser/protocols/dhcp.py

### extract CA from TLS handshakes
python3 analyser/extract_ca.py /home/hutr/2022-datasets/idle-dataset-dec /home/hutr/local-traffic-analysis/outputs/tls_dec.txt

### periodic analysis
python3 analyser/periodic_analysis.py /home/hutr/local_output/idle-dataset-dec/flow_burst/ /home/hutr/local_output/idle-dataset-dec/periodic_detection/

### count device-to-phone communication
python3 device-to-phone.py ~/local_output/idle-dataset-dec/packet_count/ .

### get ip from DHCP logs
python3 get_device_ip_addr.py