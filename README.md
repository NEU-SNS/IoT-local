# About
This repository includes scripts to analyze local traffic of smart home IoT devices for our IMC23 paper.  
For more details about our paper: https://github.com/Android-Observatory/IoT-LAN

To be updated soon! 

# Files

- `devices.txt`: a list of all devices with their MAC addresses. Add *router* manually. 
- `analysis.py`: the main script to call.
- `tagged_analysis`: 
- `protocol_statistics.py`: 
- `analyser`: analysis files 
    - `protocols_analysis.py`: protocl-wise analysis
    - `plotting.py`: plots charts.
    - `flow_extraction_new.py`: extract flows from traffic
    - `utils.py`, `constants.py`: auxiliary files.
    - `periodic_analysis.py`: peroidicity analysis
    - `protocol_identification.py`: automatically identify top-layer protocols from pcaps.
    - `all_device_analysis.py`: deprecated. protocol distribution, basic analysis, plotting, etc. 
    - `protocols`: !TODO
    - `backups.py`, `flow_extraction.py`: backup file. 
    - `vis.py`: graph visualization helper. 
- `scripts`: 
    - `extract_ca.py`: extracts certificates from TLS traffic. 
- `helper`: some other scripts
    - `setup-log.py`: get device-ip mapping from DHCP logs
    - `device-to-phone.py`: which device communicates with mobile phone 
- `connectedGraph`: 
    - `graph_generator.py`: generates connected graph visualizations. 
- `logs`: nohup log files. To remove
- `vis`: deprecated. html graph visualizations for all_device_analysis
- `outputs`: extracted certificates. Need to rename this folder. 

# Usage
### `analysis`: pyshark based protocol statistic
`python3 analysis.py ~/2022-datasets/idle-dataset-dec ~/local_output/idle-dataset-dec-new/`

### `tagged_analysis`: tagged dataset analysis
`python3 tagged_analysis.py ~/2022-datasets/tagged-local-new ~/local_output/tagged-dec/`

### `analysis`: pyshark based protocol statistic focusing on specific traffic group 
`python3 analysis.py ~/2022-datasets/idle-dataset-dec ~/local_output/idle-dataset-dec/ -a bcmc/eth_unicast/unicast/ipv6`

### `protocol_statistics.py`: log parsing of pyshark based protocol statistics (and tshark based protocol statistics as backup)
`python3 protocol_statistics.py ~/2022-datasets/idle-dataset-dec ~/local_output/idle-dataset-dec/ -plot _overall_manual_processed.txt`

### `analysis`: specific protocol-wise analysis
`python3 -u analysis.py ~/2022-datasets/idle-dataset-dec ~/local_output/idle-dataset-dec-new/ -f PROTOCOL`

`python3 analyser/protocol_parser/dhcp.py`
`python3 analyser/protocol_parser/PROTOCOL.py`

### periodic analysis
`python3 analyser/periodic_analysis.py /home/hutr/local_output/idle-dataset-dec-new/flow_burst/ /home/hutr/local_output/idle-dataset-dec-new/periodic_detection/`


## Vis
### generate connected graph
`python3 connectedGraph/graph_generator.py ~/local_output/idle-dataset-dec/tcp_output vis`
`python3 connectedGraph/graph_generator.py ~/local_output/idle-dataset-dec/udp_output vis`

### merged graph generator: 
`python3 connectedGraph/merged_html.py`

### CDF
`python3 scripts/cdf.py`

### others
`scripts/figure/ipynb`


## Scanning responses
### scanning response: what multicast/broadcast traffic has been responded 
`python3 scripts/scanning_response.py ~/local_output/idle-dataset-dec-new/flow_burst/ ~/local_output/idle-dataset-dec-new/scanning_response_2/`

### scanning response parser jupyter notebook version
`scanning_table_maker.ipynb`

### scanning response parser py version
Scanning device parser: BCMC protocols per device. Input: bcmc/bcmc/new_packet_count
`python3 scripts/scanning_device_parser.py `

Scanning response results parser: 
`python3 scripts/scanning_response_results_parser.py`

## Other Scripts:

### the stat of ip traffic only w/o router: volume, number of devices communicated with 
`python3 scripts/ip_traffic_exclude_router.py ~/local_output/idle-dataset-dec-new/tcp_output/ ~/local_output/idle-dataset-dec-new/udp_output/ ~/local_output/idle-dataset-dec-new/ip_traffic_exclude_router`

### periodic log parser. Focus on periodic multicast/broadcast traffic
`python3 scripts/periodic_log_parser.py ~/local_output/idle-dataset-dec-new/periodic_detection/ ~/local_output/idle-dataset-dec-new/periodic_detection_results/`

### port number information, from flow_burst directory
`python3 scripts/protocol_ports.py`

### extract CA from TLS handshakes
`python3 scripts/extract_ca.py /home/hutr/2022-datasets/idle-dataset-dec /home/hutr/local-traffic-analysis/outputs/tls_dec.txt`

### raw tshark results per flow
`python3 scripts/raw_tshark_flow_protocol.py in_dir out_dir`

### ndpi results parser: device per protocol and protocol per device
`python3 scripts/ndpi_results_parser.py`

### diff between tagged network graph and idle network graph
`python3 scripts/tagged_graph_difference.py ~/local_output/idle-dataset-dec-new/ ~/local_output/tagged-dec/ ./output_diff`

### some stat from the tagged dataset
`python3 scripts/tagged_dataset_stat.py`


## Helpers:

### count device-to-phone communication
`python3 helper/device-to-phone.py ~/local_output/idle-dataset-dec/packet_count/ .`

### get ip from DHCP logs
`python3 helper/get_device_ip_addr.py`

### parse protocol logs for device-ip mappings 
`python3 helper setup_log.py`
# deprecated:

### `analysis`: pyshark based protocol statistic, -b: basic analysis (plotting some distribution, to be removed)
`python3 analysis.py ~/2022-datasets/idle-dataset ~/local_output/idle-dataset/ -b`
