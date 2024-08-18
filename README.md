# About
This repository includes scripts to analyze local traffic of smart home IoT devices for our IMC23 paper.  
For more details about our paper: https://github.com/Android-Observatory/IoT-LAN


# Files

- `devices.txt`: a list of all devices with their MAC addresses. Add *router* manually. 
- `analysis.py`: the main script.
- `tagged_analysis`: analysis of controlled interaction experiments.
- `protocol_statistics.py`: see usage below.
- `analyser`: analysis files 
    - `protocols_analysis.py`: protocol analysis.
    - `plotting.py`: plot charts.
    - `flow_extraction_new.py`: extract traffic flows defined by 5-tuple from traffic.
    - `utils.py`, `constants.py`: auxiliary files.
    - `periodic_analysis.py`: traffic peroidicity analysis.
    - `protocol_identification.py`: automatically identify top-layer protocols from pcaps.
    - `all_device_analysis.py`: deprecated functions. protocol distribution, basic analysis, plotting, etc. 
    - `protocols`: analysis script of each protocol
    - `backups.py`, `flow_extraction.py`: backup file. 
    - `vis.py`: graph visualization helper. 
- `scripts`: 
    - `extract_ca.py`: extracts certificates from TLS traffic. 
- `helper`: some other scripts
    - `setup-log.py`: get device-ip mapping from DHCP logs
    - `device-to-phone.py`: which device communicates with mobile phone 
- `connectedGraph`: 
    - `graph_generator.py`: generates connected graph visualizations. 
- `outputs`: extracted TLS certificates.  

# Usage
### `analysis`: pyshark-based protocol statistic
`python3 analysis.py ~/2022-datasets/idle-dataset-dec ~/local_output/idle-dataset-dec-new/`

### `tagged_analysis`: tagged dataset (interaction dataset) analysis
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



## Scanning responses
### scanning response: what multicast/broadcast traffic has been responded 
`python3 scripts/scanning_response.py ~/local_output/idle-dataset-dec-new/flow_burst/ ~/local_output/idle-dataset-dec-new/scanning_response_2/`


### scanning response parser py version
Scanning device parser: BCMC protocols per device. Input: bcmc/bcmc/new_packet_count
`python3 scripts/scanning_device_parser.py `

Scanning response results parser: 
`python3 scripts/scanning_response_results_parser.py`

## Other Scripts:

### extract CA from TLS handshakes
`python3 scripts/extract_ca.py /home/hutr/2022-datasets/idle-dataset-dec /home/hutr/local-traffic-analysis/outputs/tls_dec.txt`


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
