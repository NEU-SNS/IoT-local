from analyser.utils import * 


def tcp_vis(results:list[str]) -> dict[str,int]:
    """_summary_

    Args:
        results (list[str]): list of packets

    Returns:
        dict[str,int]: {dst: size}
    """
    vis_output= {}
    
    for packet in results:
        if len(packet) < 12: 
            continue
        if is_broadcast(packet[5]) or is_multicast(packet[5]) or is_router(packet[4], packet[5]):
            continue
        if packet[7] == '6': 
            if packet[-1] not in vis_output:
                vis_output[packet[-1]] = 0
            vis_output[packet[-1]] += int(packet[3])

    return vis_output

def udp_vis(results:list[str]) -> dict[str,int]:
    """_summary_

    Args:
        results (list[str]): list of packets

    Returns:
        dict[str,int]: {dst: size}
    """
    vis_output= {}
    
    for packet in results:
        if len(packet) < 12: 
            continue
        if is_broadcast(packet[5]) or is_multicast(packet[5]) or is_router(packet[4], packet[5]):
            continue
        if packet[7] == '17': 
            if packet[-1] not in vis_output:
                vis_output[packet[-1]] = 0
            vis_output[packet[-1]] += int(packet[3])

    return vis_output

