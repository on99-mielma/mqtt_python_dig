import collections
import time

from scapy.all import *
from scapy.contrib.mqtt import MQTT

import CONST
import guardian.mqtt_domain as GMD

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

ERROR_MESSAGE = {
    0: 'MQTT TYPE ERROR',
    1: 'TCP PROBLEM',
    2: 'NOTHING THERE',
    3: 'WARNING THERE ARE TOO MANY PACKAGES FROM THE SAME ADDRESS',
    4: '',
}
COUNT = 0
RATE_COUNT = collections.defaultdict(int)
# 设置监听的网络接口和过滤条件
interface = CONST.INTERFACE  # 替换为你的网络接口名称
filter_rule = f"tcp port {CONST.DST_PORT}"


def package_count(package: GMD.MQTTPackage):
    source = package.source_union
    if source is None:
        raise Exception(ERROR_MESSAGE.get(1))
    RATE_COUNT[source] += 1


def refresh_rate_count():
    global RATE_COUNT
    del RATE_COUNT
    RATE_COUNT = collections.defaultdict(int)


def show_mqtt_package(packet: Packet):
    if packet.haslayer(MQTT):
        package_count(package=GMD.MQTTPackage(packet))


def opening_sniff(interval=1, endcount=10000, warning_line=600.0):
    while True:
        global COUNT
        COUNT += 1
        if COUNT > endcount:
            break
        logging.info(
            msg=f'sniff on!!! mode = <DETECT FLOOD> count = {COUNT}'
        )
        capture_start_time = time.time()
        sniff(iface=interface, filter=filter_rule, prn=show_mqtt_package, session=IPSession, store=False,
              timeout=interval)
        capture_end_time = time.time()
        capture_duration = capture_end_time - capture_start_time
        if len(RATE_COUNT) == 0:
            logging.info(
                msg=ERROR_MESSAGE.get(2)
            )
        else:
            for k, v in RATE_COUNT.items():
                rate = v / capture_duration
                temp_suspect = ''
                if rate > warning_line:
                    temp_suspect = ERROR_MESSAGE.get(3)
                logging.info(
                    msg=f'DURATION TIME = <{capture_duration}> - PACKAGE KEY = <{k}> - PACKAGE COUNT = <{v}> - PACKAGE RATE = <{rate}>{temp_suspect}\n'
                )
        refresh_rate_count()


if __name__ == '__main__':
    opening_sniff(interval=1)
