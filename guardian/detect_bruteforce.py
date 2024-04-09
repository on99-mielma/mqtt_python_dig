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
    2: 'BRUTEFORCE DETECTED!',
    3: 'MISSING USERNAME OR PASSWORD !',
    4: 'BRUTEFORCE SUSPECT!',
    5: 'BLOCK!'
}

# 在数据库中存储的已有的用户密码集
DATABASE_USER_PASS_DICT = {}
USER_SET = set(list(DATABASE_USER_PASS_DICT.keys()))
PASS_SET = set(list(DATABASE_USER_PASS_DICT.values()))
SUSPECT_COUNT = 0
# 设置监听的网络接口和过滤条件
interface = CONST.INTERFACE  # 替换为你的网络接口名称
filter_rule = f"tcp port {CONST.DST_PORT}"


def add_to_blocklist(address: str):
    import guardian.block_list as bl
    bl.init_add_save(address=address)


def get_blocklist():
    import guardian.block_list as bl
    return bl.static_get()


def add_refresh(address: str):
    add_to_blocklist(address)
    return get_blocklist()


GLOBAL_BLOCK_JSON, GLOBAL_BLOCK_IP_SET, GLOBAL_BLOCK_TCPIP_SET = get_blocklist()


def ratio_detect(value: str, mode=0, address=None):
    global GLOBAL_BLOCK_JSON, GLOBAL_BLOCK_IP_SET, GLOBAL_BLOCK_TCPIP_SET
    if address in GLOBAL_BLOCK_IP_SET or address in GLOBAL_BLOCK_TCPIP_SET:
        logging.info(
            msg=f'{ERROR_MESSAGE.get(5)}'
        )
        return None
    global SUSPECT_COUNT
    MaxRatio = 0.0
    if mode == 0:
        for u in USER_SET:
            s = difflib.SequenceMatcher(
                isjunk=lambda x: x == ' ',
                a=u,
                b=value,
                autojunk=True
            ).ratio()
            MaxRatio = max(MaxRatio, s)
    else:
        for u in PASS_SET:
            s = difflib.SequenceMatcher(
                isjunk=lambda x: x == ' ',
                a=u,
                b=value,
                autojunk=True
            ).ratio()
            MaxRatio = max(MaxRatio, s)
    if MaxRatio < 0.5:
        logging.info(
            msg=f'{ERROR_MESSAGE.get(4)}'
        )
        SUSPECT_COUNT += 1
        if SUSPECT_COUNT > 5:
            logging.info(
                msg=f'{ERROR_MESSAGE.get(2)}'
            )
            GLOBAL_BLOCK_JSON, GLOBAL_BLOCK_IP_SET, GLOBAL_BLOCK_TCPIP_SET = add_refresh(address=address)

    else:
        SUSPECT_COUNT = max(0, SUSPECT_COUNT - 3)


def show_mqtt_package(packet: Packet):
    if packet.haslayer(MQTT):
        newpacket = GMD.MQTTPackage(packet=packet)
        src_union = newpacket.source_union
        if newpacket.type == 1:
            subpacket = newpacket.subMQTTPackage
            username = None
            password = None
            if subpacket.protolevel == 5:
                username = subpacket.userName
                password = subpacket.password
            else:
                username = subpacket.username
                password = subpacket.password
            if username is None or password is None:
                logging.info(
                    msg=f'{ERROR_MESSAGE.get(3)}'
                )
            else:
                if username is not None:
                    ratio_detect(username, 0, address=src_union)
                if password is not None:
                    ratio_detect(password, 1, address=src_union)


def opening_sniff():
    logging.info(
        msg='sniff on!!! mode = <ANTI BRUTEFORCE>\n'
    )
    sniff(iface=interface, filter=filter_rule, prn=show_mqtt_package, session=IPSession, store=False)


if __name__ == '__main__':
    opening_sniff()
    # blocklist = get_blocklist()
    # print(blocklist)
    # add_to_blocklist('192.168.31.233')
    # blocklist = get_blocklist()
    # print(blocklist)
