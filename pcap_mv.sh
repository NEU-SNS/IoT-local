#!bin/bash
####
#### This component for direct file to dns txt
# out_file = dns_candidates.txt
# while read device
# do 
# 	echo device
# 	ls /traffic/by-name/$device/unctrl/2021-09-0*.pcap >> idle_files.txt
# 	ls /traffic/by-name/$device/ctrl1/2021-09-0*.pcap >> idle_files.txt
# 	ls /traffic/by-name/$device/ctrl2/2021-09-0*.pcap >> idle_files.txt
#     # ls /traffic/by-name/$device/ctrl2/2021-08*.pcap >> dns_candidates_all.txt
# done < 2021devices.txt

scp -r tianrui@129.10.227.207:/home/tianrui/2022-datasets/local_traffic/ /home/hutr/local_traffic
#while read device
#do 
	
	# echo $new_file $device
#	scp tianrui@129.10.227.207:/home/ubuntu//$device/unctrl/ $file

# done < 2021devices.txt

# ##########
# out_dir=/home/tianrui/auto_summer2021/dns_pcap/
# new_file=''
# while read device
# do 
# 	mkdir $out_dir/$device

# while read file
# do 
# 	# echo $file | cut -d '/' -f 6
# 	device=$(echo $file|cut -d '/' -f 4)
# 	new_file=$(echo $file|cut -d '/' -f 6)
# 	echo $new_file $device
# 	mkdir -p $out_dir/$device/unctrl
# 	tshark -r $file -Y 'dns||dns.a||ssl.handshake.extensions_server_name' -w $out_dir/$device/unctrl/$new_file -F pcap
# done < dns_candidates.txt

# while read file
# do 
# 	device=$(echo $file|cut -d '/' -f 4)
# 	# echo $device
# 	if [ ! -f $out_dir/$device/unctrl/$device.pcap ]; then
# 		mergecap $out_dir/$device/unctrl/*.pcap -w $out_dir/$device/unctrl/$device.pcap
# 	fi
# done < dns_candidates.txt




