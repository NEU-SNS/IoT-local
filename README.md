# About
This repository includes scripts to analyze local traffic of smart home IoT devices.  

# Files

`devices.txt`: all devices with their MAC addresses.
`analysis.py`: the main analysis script.
`graph_generator.py`: generates connected graph visualizations. 
`plotting.py`: plots charts.
`extract_ca.py`: extracts certificates from TLS traffic. 
`flow_extraction.py`: extract flows from traffic
`utils.py` `constants.py`: auxiliary files.
`periodic_detection_dec_1s+1hour.py`: !TODO

# Usage
### analysis
python3 analysis.py ~/2022-datasets/idle-dataset ~/local_output/idle-dataset/

### generate connected graph
python3 graph_generator.py ~/local_output/idle-dataset/tcp_output vis
