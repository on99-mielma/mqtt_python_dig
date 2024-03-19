import logging
from scapy.all import *
from scapy.contrib.mqtt import MQTT
from scapy.layers.inet import TCP

import CONST
import mitm.mitm_5_learn as m5

logging.basicConfig(
    level=logging.NOTSET,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

ERROR_MESSAGE = {
    0: 'MQTT TYPE ERROR',
    1: 'TCP PROBLEM'
}

# 设置监听的网络接口和过滤条件
interface = "Realtek PCIe 2.5GbE Family Controller"  # 替换为你的网络接口名称
filter_rule = f"tcp port {CONST.DST_PORT}"


def seek_tcp_package(package):
    if package.haslayer(TCP):
        return package
    else:
        raise Exception(ERROR_MESSAGE.get(1))


def show_mqtt_package(packet: Packet):
    if packet.haslayer(MQTT):
        checkTCP = seek_tcp_package(packet)
        payloadLen = m5.seek_package_tcp_payload(checkTCP)
        packetHex = m5.fixHex(checkTCP)
        typeNum, typeMsg = m5.TcpPacket(payload_len=payloadLen, packet=packetHex).mqttType
        logging.debug(
            msg=f'packet <{packet}> - <num:{typeNum},msg:{typeMsg}> - MQTT?=<{packet.haslayer(MQTT)}> - Raw?=<{packet.haslayer(Raw)} - package '
                f'original data = <{packet.original}>> '
        )


def opening_sniff():
    logging.debug(
        msg='sniff on!!!\n'
    )
    sniff(iface=interface, filter=filter_rule, prn=show_mqtt_package, session=IPSession, store=False)


if __name__ == '__main__':
    opening_sniff()
