# About
This repository includes scripts to analyze local traffic of smart home IoT devices.  

# Files

- `devices.txt`: all devices with their MAC addresses.
- `analysis.py`: the main analysis script.
- `graph_generator.py`: generates connected graph visualizations. 
- `plotting.py`: plots charts.
- `extract_ca.py`: extracts certificates from TLS traffic. 
- `flow_extraction.py`: extract flows from traffic
- `utils.py` `constants.py`: auxiliary files.
- `periodic_detection_dec_1s+1hour.py`: !TODO

# Usage

### analysis: pyshark based protocol statistic, basic analysis (plotting distribution)
python3 analysis.py ~/2022-datasets/idle-dataset-nov ~/local_output/idle-dataset-nov/ -b


### tshark based protocol statistic and log parsing of pyshark based protocol statistic
python3 protocol_statistics.py ~/2022-datasets/idle-dataset-nov ~/local_output/idle-dataset-nov/


### protocol-wise analysis
python3 analysis.py ~/2022-datasets/idle-dataset-nov ~/local_output/idle-dataset-nov/ -f PROTOCOL

### generate connected graph
python3 graph_generator.py ~/local_output/idle-dataset-nov/tcp_output vis

### parse protocol logs
python3 analyser/protocols/dhcp.py

### extract CA from TLS handshakes
python3 analyser/extract_ca.py 
