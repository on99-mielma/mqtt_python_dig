from scapy.all import *
from scapy.contrib.mqtt import MQTT

import CONST
import guardian.mqtt_domain as GMD

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
THEME = 'FUZZING'
ERROR_MESSAGE = {
    0: 'MQTT TYPE ERROR',
    1: 'TCP PROBLEM',
    2: f'{THEME} DETECTED!',
    3: f'MISSING PRECONDITIONS!',
    4: f'{THEME} SUSPECT!',
    5: f'{THEME} SUSPECT! REASON:<MULTIPLE CONNECT or MULTIPLE CONNECT_ACK MISSING or HAD BENN ACK>',
    6: f'{THEME} SUSPECT! REASON:<MISSING CONNECT>',
    7: f'{THEME} SUSPECT! REASON:<MESSAGE HAD BEEN ACK/REC>',
    8: f'{THEME} SUSPECT! REASON:<QOS PROBLEM>',
    9: f'{THEME} SUSPECT! REASON:<WRONG ACK WHEN THERE IS NOT ANY PUBLISH>',
    10: f'{THEME} SUSPECT! REASON:<MULTIPLE PUBLISH ACK/REC/REL/COMP>',
    11: f'{THEME} SUSPECT! REASON:<MISSING QOS2 KEY STEP>',
    12: f'{THEME} SUSPECT! REASON:<MULTIPLE SUBSCRIBE/UNSUBSCRIBE>',
    13: f'{THEME} SUSPECT! REASON:<MISSING SUBSCRIBE/UNSUBSCRIBE>',
    14: f'{THEME} SUSPECT! REASON:<MULTIPLE PING>',
    15: f'{THEME} SUSPECT! REASON:<MISSING PING REQUEST>',
}

"""
配对条件
CONNECT CONNECT_ACK DISCONNECT
SUBSCRIBE SUBSCRIBE_ACK
UNSUBSCRIBE UNSUBSCRIBE_ACK
PING_REQUEST PING_RESPONSE
PUBLISH PUBLISH_ACK (QOS == 1)
PUBLISH PUBLISH_REC PUBLISH_REL PUBLISH_COMP (QOS == 2)
"""
SUSPECT_COUNT = 0
# 设置监听的网络接口和过滤条件
interface = CONST.INTERFACE  # 替换为你的网络接口名称
filter_rule = f"tcp port {CONST.DST_PORT}"

CONNECT_DICT = {}
PUBLISH_QOS_1 = {}
PUBLISH_QOS_2 = {}
SUBSCRIBE_DICT = {}
UNSUBSCRIBE_DICT = {}
PING_DICT = {}


def match_package(package: GMD.MQTTPackage, mode=0):
    try:
        if mode is None or mode == 0:
            raise Exception(ERROR_MESSAGE.get(0))
        if mode == 1:
            ans = CONNECT_DICT.get(package.source_union, None)
            if ans is None:
                CONNECT_DICT[package.source_union] = 1
            else:
                CONNECT_DICT[package.source_union] += 1
                if CONNECT_DICT.get(package.source_union) > 3:
                    raise Exception(ERROR_MESSAGE.get(5))
        elif mode == 2:
            ans = CONNECT_DICT.get(package.destination_union, None)
            if ans is None:
                raise Exception(ERROR_MESSAGE.get(6))
            else:
                CONNECT_DICT[package.destination_union] += 10
        elif mode == 3:
            qos = package.qos
            if qos == 1:
                msgid = package.subMQTTPackage.msgid
                pq1 = PUBLISH_QOS_1.get(msgid, None)
                if pq1 is None:
                    PUBLISH_QOS_1[msgid] = [True, False]
                elif PUBLISH_QOS_1.get(msgid)[-1]:
                    raise Exception(ERROR_MESSAGE.get(7))
            elif qos == 2:
                msgid = package.subMQTTPackage.msgid
                pq2 = PUBLISH_QOS_2.get(msgid, None)
                if pq2 is None:
                    PUBLISH_QOS_2[msgid] = [True, False, False, False]
                elif not all(PUBLISH_QOS_2.get(msgid)[1:]):
                    raise Exception(ERROR_MESSAGE.get(7))
        elif mode == 4:
            msgid = package.subMQTTPackage.msgid
            pq1 = PUBLISH_QOS_1.get(msgid, None)
            if pq1 is None:
                raise Exception(ERROR_MESSAGE.get(9))
            elif not pq1[-1]:
                w = pq1
                w[-1] = True
                PUBLISH_QOS_1[msgid] = w
            else:
                raise Exception(ERROR_MESSAGE.get(10))
        elif mode == 5:
            msgid = package.subMQTTPackage.msgid
            pq2 = PUBLISH_QOS_2.get(msgid, None)
            if pq2 is None:
                raise Exception(ERROR_MESSAGE.get(9))
            elif pq2[1]:
                raise Exception(ERROR_MESSAGE.get(10))
            elif not pq2[1]:
                w = pq2
                w[1] = True
                PUBLISH_QOS_2[msgid] = w
        elif mode == 6:
            msgid = package.subMQTTPackage.msgid
            pq2 = PUBLISH_QOS_2.get(msgid, None)
            if pq2 is None:
                raise Exception(ERROR_MESSAGE.get(9))
            elif not pq2[1]:
                raise Exception(ERROR_MESSAGE.get(11))
            elif pq2[2]:
                raise Exception(ERROR_MESSAGE.get(10))
            elif not pq2[2]:
                w = pq2
                w[2] = True
                PUBLISH_QOS_2[msgid] = w
        elif mode == 7:
            msgid = package.subMQTTPackage.msgid
            pq2 = PUBLISH_QOS_2.get(msgid, None)
            if pq2 is None:
                raise Exception(ERROR_MESSAGE.get(9))
            elif not pq2[1]:
                raise Exception(ERROR_MESSAGE.get(11))
            elif not pq2[2]:
                raise Exception(ERROR_MESSAGE.get(11))
            elif pq2[3]:
                raise Exception(ERROR_MESSAGE.get(10))
            elif not pq2[3]:
                w = pq2
                w[3] = True
                PUBLISH_QOS_2[msgid] = w
        elif mode == 8:
            msgid = package.subMQTTPackage.msgid
            sd = SUBSCRIBE_DICT.get(msgid, None)
            if sd is None:
                SUBSCRIBE_DICT[msgid] = 1
            else:
                SUBSCRIBE_DICT[msgid] += 1
                if SUBSCRIBE_DICT.get(msgid) > 3:
                    raise Exception(ERROR_MESSAGE.get(12))
        elif mode == 9:
            msgid = package.subMQTTPackage.msgid
            sd = SUBSCRIBE_DICT.get(msgid, None)
            if sd is None:
                raise Exception(ERROR_MESSAGE.get(13))
            else:
                SUBSCRIBE_DICT[msgid] += 10
        elif mode == 10:
            msgid = package.subMQTTPackage.msgid
            ud = UNSUBSCRIBE_DICT.get(msgid, None)
            if ud is None:
                UNSUBSCRIBE_DICT[msgid] = 1
            else:
                UNSUBSCRIBE_DICT[msgid] += 1
                if UNSUBSCRIBE_DICT.get(msgid) > 3:
                    raise Exception(ERROR_MESSAGE.get(12))
        elif mode == 11:
            msgid = package.subMQTTPackage.msgid
            ud = UNSUBSCRIBE_DICT.get(msgid, None)
            if ud is None:
                raise Exception(ERROR_MESSAGE.get(13))
            else:
                UNSUBSCRIBE_DICT[msgid] += 10
        elif mode == 12:
            ans = PING_DICT.get(package.source_union, None)
            if ans is None:
                PING_DICT[package.source_union] = 1
            else:
                PING_DICT[package.source_union] += 1
                if PING_DICT.get(package.source_union) > 2:
                    raise Exception(ERROR_MESSAGE.get(14))
        elif mode == 13:
            ans = PING_DICT.get(package.destination_union, None)
            if ans is None:
                raise Exception(ERROR_MESSAGE.get(15))
            else:
                del PING_DICT[package.destination_union]
        elif mode == 14:
            ans = CONNECT_DICT.get(package.source_union, None)
            if ans is None:
                raise Exception(ERROR_MESSAGE.get(6))
            else:
                del CONNECT_DICT[package.source_union]
    except AttributeError as ae:
        print(f'AttributeError with <{ae}>')
    except Exception as e:
        print(f'Exception with <{e}>')


def show_mqtt_package(packet: Packet):
    if packet.haslayer(MQTT):
        package = GMD.MQTTPackage(packet=packet)
        type_mode = package.type
        match_package(package=package, mode=type_mode)


def opening_sniff():
    logging.info(
        msg=f'sniff on!!! mode = <ANTI {THEME}>\n'
    )
    sniff(iface=interface, filter=filter_rule, prn=show_mqtt_package, session=IPSession, store=False)


if __name__ == '__main__':
    opening_sniff()
