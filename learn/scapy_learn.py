from scapy.contrib.mqtt import MQTT, MQTTConnect, MQTTPublish, MQTTSubscribe, MQTTUnsubscribe, MQTTConnack, MQTTPuback, \
    MQTTSuback, MQTTUnsuback, MQTTPubrec, MQTTPubrel, MQTTPubcomp, MQTTDisconnect
from scapy.layers.inet import IP, TCP
from scapy.all import *
import random
import randomIP
import logging

logging.basicConfig(
    level=logging.NOTSET,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

destination = '192.168.31.244'
source = '192.168.31.233'
client_id = "scapy_test"
topic = "python/shit"
# topic = "test0"
mac_addr = '00:0c:29:33:ec:cb'


# arp_entry = ARP(pdst=destination,hwdst=mac_addr)
# arp_entry.op = 2
# arp_entry.hwlen = 6
# arp_add(arp_entry)

# 构造带有IP以及TCP的MQTT CONNECT报文
def build_mqtt_connect_packet(client_id, src_ip, src_port, target_ip, target_port):
    tcp = TCP(dport=target_port, sport=src_port)
    tcp.flags = 'A'
    tcp.flags |= 'P'
    randomTOTlen = 5
    diy = bytes(
        [randomTOTlen, 0x11] + [0x00 for _ in range(randomTOTlen - 1)] + [0x00, len(client_id)])
    packet = IP(dst=f"{target_ip}", src=f'{src_ip}') / tcp / MQTT(type=1) / MQTTConnect(
        protoname='MQTT',
        usernameflag=0,
        passwordflag=0,
        willretainflag=0,
        willQOSflag=0,
        willflag=0,
        cleansess=1,
        reserved=0,
        klive=60,
        clientId=client_id,
        clientIdlen=RawVal(diy)
    )
    print('*' * 100)
    packet.show()
    print('*' * 100)
    return packet


# 构造MQTT CONNECT报文
def build_mqtt_connect_packet_only(client_id):
    randomTOTlen = 5
    diy = bytes(
        [randomTOTlen, 0x11] + [0x00 for _ in range(randomTOTlen - 1)] + [0x00, len(client_id)])
    # packet = IP(dst=f"{destination}", src=f'{source}') / tcp / MQTT(type=1) / MQTTConnect(
    #     protoname='MQTT',
    #     usernameflag=0,
    #     passwordflag=0,
    #     willretainflag=0,
    #     willQOSflag=0,
    #     willflag=0,
    #     cleansess=1,
    #     reserved=0,
    #     klive=60,
    #     clientId=client_id,
    #     clientIdlen=RawVal(diy)
    # )
    packet = MQTT(type=1) / MQTTConnect(
        protoname='MQTT',
        usernameflag=0,
        passwordflag=0,
        willretainflag=0,
        willQOSflag=0,
        willflag=0,
        cleansess=1,
        reserved=0,
        klive=60,
        clientId=client_id,
        clientIdlen=RawVal(diy)
    )
    logging.debug(
        msg=f'CONNECT PACKET BUILD <{packet}>'
    )
    # print('*' * 100)
    # packet.show()
    # print('*' * 100)
    return packet


# 发送MQTT报文
def send_mqtt_packet(packet):
    send(packet)


# 样例
def CONNECT_TEST_0():
    mqtt_connect_packet = build_mqtt_connect_packet(client_id, src_ip=source, src_port=16665, target_ip=destination,
                                                    target_port=1883)
    send_mqtt_packet(mqtt_connect_packet)


def PUBLISH_TEST_0(destination: str, topic: str):
    # 构建MQTT publish消息
    tcp = TCP(dport=1883, sport=16665)
    tcp.flags = 'P'
    tcp.flags |= 'A'
    mqtt = MQTT(
        type=3,
        DUP=0,
        QOS=0,
        RETAIN=0
    )
    # 发送MQTT publish消息
    package = IP(dst=destination, src=f'{source}') / tcp / mqtt / MQTTPublish(topic=topic,
                                                                              value='01234567899876543210')
    send(package)
    print('*' * 100)
    package.show()
    print('*' * 100)


def SOCKET_TEST_0():
    """
    USELESS
    :return:
    """
    # 构建TCP SYN数据包
    ip = IP(src="192.168.31.233", dst="192.168.31.244")
    tcp = TCP(sport=1234, dport=80, flags="S", seq=1000)

    # 发送TCP SYN数据包并接收响应
    syn_ack = sr1(ip / tcp)

    if syn_ack:
        # 解析响应数据包
        if syn_ack.haslayer(TCP) and syn_ack.getlayer(TCP).flags == "SA":
            print("TCP connection established")
        else:
            print("TCP connection failed")
    else:
        print("No response received")


def CONNECT_ATTACK_EMU_0():
    """
    sucked
    :return:
    """
    while True:
        temp_client_id = randomIP.RANDOM_NAME(suffix='MQTT_')
        temp_target_ip = '192.168.31.244'
        temp_target_port = 1883
        temp_src_ip = randomIP.IPV4()
        temp_src_port = random.randint(12000, 16665)
        ans = send(
            build_mqtt_connect_packet(temp_client_id, temp_src_ip, temp_src_port, temp_target_ip, temp_target_port))
        print('M' * 64)
        print(ans)
        print('W' * 64)


def PUBLISH_ONLY_TEST_0(topic, value):
    # 构建MQTT publish消息
    mqtt = MQTT(
        type=3,
        DUP=0,
        QOS=0,
        RETAIN=0
    )
    # 发送MQTT publish消息
    package = mqtt / MQTTPublish(topic=topic,
                                 value=chr(0) + value)
    # print('*' * 100)
    # package.show()
    # print('*' * 100)
    logging.debug(
        msg=f'PUBLISH PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def AUTO_MQTT_HEAD(mqtt_type=0):
    # Cas Publish
    if mqtt_type == 3:
        qos = random.randint(0, 2)
        retain = random.randint(0, 1)
        if qos == 0 or qos == 2:
            dup = 0
        else:
            dup = random.randint(0, 1)
    # Cas Subscribe
    if mqtt_type == 8:
        dup = 0
        qos = 1
        retain = 0
    # Autres cas
    else:
        dup = 0
        qos = 0
        retain = 0

    # mqtt_fields = MQTT.MQTT(type=mqtt_type,
    #                         DUP=0,
    #                         QOS=0,
    #                         RETAIN=0,
    #                         len=None)
    mqtt_head_packet = MQTT(type=mqtt_type,
                            DUP=dup,
                            QOS=qos,
                            RETAIN=retain,
                            len=None)
    logging.debug(
        msg=f'MQTT HEAD PACKET BUILD <{mqtt_head_packet}> - <{mqtt_head_packet.fields}>'
    )
    return mqtt_head_packet


def Topic_Suffix(retain_handling=0, retain_as_published=0, no_local=0, qos=0):
    """
    字段检查
    :param retain_handling:
    :param retain_as_published:
    :param no_local:
    :param qos:
    :return:
    """
    if not (0 <= retain_handling <= 3):
        raise Exception('Check 0<=retain_handling<=3')
    if not (0 <= retain_as_published <= 1):
        raise Exception('Check 0<=retain_as_published<=1')
    if not (0 <= no_local <= 1):
        raise Exception('Check 0<=no_local<=1')
    if not (0 <= qos <= 3):
        raise Exception('Check 0<=qos<=3')
    options = 0
    options |= qos
    options |= (no_local << 2)
    options |= (retain_as_published << 3)
    options |= (retain_handling << 4)
    return options


def Fresh_Topic(topics: List[str], mqtt_type=8):
    """
    报文间隔符修正
    :param topics:
    :param mqtt_type:
    :return:
    """
    n = len(topics)
    index1 = 0
    while index1 < n:
        tempLen = len(topics[index1])
        if mqtt_type == 8:
            if index1 == 0:
                topics[index1] = chr(0) + chr(tempLen >> 8) + chr(tempLen & 0x00FF) + topics[index1] + chr(
                    Topic_Suffix())
            else:
                topics[index1] = chr(tempLen >> 8) + chr(tempLen & 0x00FF) + topics[index1] + chr(
                    Topic_Suffix())
        elif mqtt_type == 10:
            if index1 == 0:
                topics[index1] = chr(0) + chr(tempLen >> 8) + chr(tempLen & 0x00FF) + topics[index1]
            else:
                topics[index1] = chr(tempLen >> 8) + chr(tempLen & 0x00FF) + topics[index1]
        index1 += 1
    return topics


def SUBSCRIBE_ONLY_TEST_0(topics=None):
    if topics is None:
        topics = ['#']
    msgid = random.randint(1, 65533)
    topics = Fresh_Topic(topics, mqtt_type=8)
    package = AUTO_MQTT_HEAD(mqtt_type=8) / MQTTSubscribe(msgid=msgid, topics=topics)
    logging.debug(
        msg=f'SUBSCRIBE PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def UNSUBSCRIBE_ONLY_TEST_0(topics=None):
    if topics is None:
        topics = ['#']
    topics = Fresh_Topic(topics, mqtt_type=10)
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=10) / MQTTUnsubscribe(msgid=msgid, topics=topics)
    logging.debug(
        msg=f'UNSUBSCRIBE PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def CONEECTACK_ONLY_TEST_0():
    """
    sessPresentFlag?
    retcode::
    0	0x00连接已接受	连接已被服务端接受
    1	0x01连接已拒绝，不支持的协议版本	服务端不支持客户端请求的MQTT协议级别
    2	0x02连接已拒绝，不合格的客户端标识符	客户端标识符是正确的UTF-8编码，但服务端不允许使用
    3	0x03连接已拒绝，服务端不可用	网络连接已建立，但MQTT服务不可用
    4	0x04连接已拒绝，无效的用户名或密码	用户名或密码的数据格式无效
    5	0x05连接已拒绝，未授权	客户端未被授权连接到此服务器
    6-255		保留
    :return:
    """
    # length = 16
    ID_Maximum_Packet_Size = 0x27
    ID_Maximum_Packet_Size_Value = random.randint(0x0fffffff, 0xffffffff)

    def UNION_ID_Maximum_Packet_Size():
        return [
            ID_Maximum_Packet_Size,
            (ID_Maximum_Packet_Size_Value >> 6) & 0xff,
            (ID_Maximum_Packet_Size_Value >> 4) & 0xff,
            (ID_Maximum_Packet_Size_Value >> 2) & 0xff,
            ID_Maximum_Packet_Size_Value & 0xff,
        ]

    ID_Retain_Available = 0x25
    ID_Retain_Available_Value = 1  # 0 or 1

    def UNION_ID_Retain_Available():
        return [
            ID_Retain_Available,
            ID_Retain_Available_Value & 0xff
        ]

    ID_Shared_Subscription_Available = 0x2a
    ID_Shared_Subscription_Available_Value = 1  # 0 or 1

    def UNION_ID_Shared_Subscription_Available():
        return [
            ID_Shared_Subscription_Available,
            ID_Shared_Subscription_Available_Value & 0xff
        ]

    ID_Subscription_Identifier_Available = 0x29
    ID_Subscription_Identifier_Available_Value = 1  # 0 or 1

    def UNION_ID_Subscription_Identifier_Available():
        return [
            ID_Subscription_Identifier_Available,
            ID_Subscription_Identifier_Available_Value & 0xff
        ]

    ID_Topic_Alias_Maximum = 0x22
    ID_Topic_Alias_Maximum_Value = random.randint(0x0fff, 0xffff)

    def UNION_ID_Topic_Alias_Maximum():
        return [
            ID_Topic_Alias_Maximum,
            (ID_Topic_Alias_Maximum_Value >> 2) & 0xff,
            (ID_Topic_Alias_Maximum_Value >> 0) & 0xff,
        ]

    ID_Wildcard_Subscription_Available = 0x28
    ID_Wildcard_Subscription_Available_Value = 1  # 0 or 1

    def UNION_ID_Wildcard_Subscription_Available():
        return [
            ID_Wildcard_Subscription_Available,
            ID_Wildcard_Subscription_Available_Value & 0xff
        ]

    ID_Topic_Alias = 0x23
    ID_Topic_Alias_Value = random.randint(1, 0xffff)

    def UNION_ID_Topic_Alias():
        return [
            ID_Topic_Alias,
            (ID_Topic_Alias_Value >> 2) & 0xff,
            (ID_Topic_Alias_Value >> 0) & 0xff,
        ]

    ID_Payload_Format_Indicator = 0x01
    ID_Payload_Format_Indicator_Value = random.randint(1, 0xff)

    def UNION_ID_Payload_Format_Indicator():
        return [
            ID_Payload_Format_Indicator,
            ID_Payload_Format_Indicator_Value & 0xff
        ]

    ID_User_Property = 0x26
    ID_User_Property_Value = random.randint(1, 0xffff)

    def UNION_ID_User_Property():
        return [
            ID_User_Property,
            (ID_User_Property_Value >> 2) & 0xff,
            (ID_User_Property_Value >> 0) & 0xff,
        ]

    ID_Receive_Maximum = 0x21
    ID_Receive_Maximum_Value = random.randint(0x0fff, 0xffff)

    def UNION_ID_Receive_Maximum():
        return [
            ID_Receive_Maximum,
            (ID_Receive_Maximum_Value >> 2) & 0xff,
            (ID_Receive_Maximum_Value >> 0) & 0xff,
        ]

    ID_Maximum_QoS = 0x24
    ID_Maximum_QoS_Value = random.randint(0, 2)

    def UNION_ID_Maximum_QoS():
        return [
            ID_Maximum_QoS,
            ID_Maximum_QoS_Value & 0xff
        ]

    ID_Publication_Expiry_Interval = 0x02
    ID_Publication_Expiry_Interval_Value = random.randint(0x0fffffff, 0xffffffff)

    def UNION_ID_Publication_Expiry_Interval():
        return [
            ID_Publication_Expiry_Interval,
            (ID_Publication_Expiry_Interval_Value >> 6) & 0xff,
            (ID_Publication_Expiry_Interval_Value >> 4) & 0xff,
            (ID_Publication_Expiry_Interval_Value >> 2) & 0xff,
            ID_Publication_Expiry_Interval_Value & 0xff,
        ]

    nums = UNION_ID_Maximum_Packet_Size() + \
           UNION_ID_Retain_Available() + \
           UNION_ID_Shared_Subscription_Available() + \
           UNION_ID_Subscription_Identifier_Available() + \
           UNION_ID_Topic_Alias_Maximum() + \
           UNION_ID_Wildcard_Subscription_Available()
    package = AUTO_MQTT_HEAD(mqtt_type=2) / MQTTConnack(sessPresentFlag=1, retcode=0) / Raw(bytes([len(nums)] + nums))
    logging.debug(
        msg=f'CONEECTACK PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def PUBACK_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=4) / MQTTPuback(msgid=msgid)
    logging.debug(
        msg=f'PUBACK PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def SUBACK_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=9) / MQTTSuback(msgid=msgid, retcode=0)
    logging.debug(
        msg=f'PUBACK PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def UNSUBACK_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    retcode = 0x00
    package = AUTO_MQTT_HEAD(mqtt_type=11) / MQTTUnsuback(msgid=msgid) / Raw(bytes([retcode]))
    logging.debug(
        msg=f'UNSUBACK PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def PUBREC_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=5) / MQTTPubrec(msgid=msgid)
    logging.debug(
        msg=f'PUBREC PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def PUBREL_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=6) / MQTTPubrel(msgid=msgid)
    logging.debug(
        msg=f'PUBREL PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def PUBCOMP_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=7) / MQTTPubcomp(msgid=msgid)
    logging.debug(
        msg=f'PUBCOMP PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package

def PINGREQ_ONLY_TEST_0():
    package = AUTO_MQTT_HEAD(mqtt_type=12)
    logging.debug(
        msg=f'PINGREQ PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package

def PINGRESP_ONLY_TEST_0():
    package = AUTO_MQTT_HEAD(mqtt_type=13)
    logging.debug(
        msg=f'PINGRESP PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def DISCONNECT_ONLY_TEST_0():
    # easy mode
    return AUTO_MQTT_HEAD(mqtt_type=14) / MQTTDisconnect()


def DISCONNECT_ONLY_TEST_1():
    # hard core
    # Reason Code: Normal disconnection (0) # retcode < 1 only 0
    nums = [0x00, 0x00]
    package = AUTO_MQTT_HEAD(mqtt_type=14) / MQTTDisconnect() / Raw(bytes(nums))
    logging.debug(
        msg=f'PUBCOMP PACKET BUILD <{package}> - <{package.fields}>'
    )
    return package


def create_socket(ip):
    s = socket.socket()
    print(ip)
    s.connect((ip, 1883))
    ss = StreamSocket(s, Raw)
    return ss


def send_scenarii(packets, ip):
    # Socket creation
    ss = create_socket(ip)

    # Senfind packet for each scenario
    for packet in packets:
        print('Send packet type: ', packet.type)
        if packet.type == 1:
            print('****', packet.protolevel)
            ss.sr1(packet)
        else:
            ss.send(packet)

    # Stopping connection
    print("END")
    ss.close()


def GEN_RANDOM_PACKAGE():
    ERR_MESSAGE = {
        0: 'NUMBER ERROR'
    }
    CONTROL_PACKET_TYPE = {
        1: 'CONNECT',
        2: 'CONNACK',
        3: 'PUBLISH',
        4: 'PUBACK',
        5: 'PUBREC',
        6: 'PUBREL',
        7: 'PUBCOMP',
        8: 'SUBSCRIBE',
        9: 'SUBACK',
        10: 'UNSUBSCRIBE',
        11: 'UNSUBACK',
        12: 'PINGREQ',
        13: 'PINGRESP',
        14: 'DISCONNECT',
        15: 'AUTH'  # Added in v5.0
    }
    number = random.randint(0, 150) % 15 + 1
    if number == 1:
        return build_mqtt_connect_packet_only(randomIP.RANDOM_NAME(suffix='MQTT_'))
    elif number == 2:
        return CONEECTACK_ONLY_TEST_0()
    elif number == 3:
        return PUBLISH_ONLY_TEST_0(topic=randomIP.RANDOM_NAME(suffix='python/', randomLen=random.randint(1, 10)),
                                   value=randomIP.RANDOM_NAME(randomLen=random.randint(10, 20)))
    elif number == 4:
        return PUBACK_ONLY_TEST_0()
    elif number == 5:
        return PUBREC_ONLY_TEST_0()
    elif number == 6:
        return PUBREL_ONLY_TEST_0()
    elif number == 7:
        return PUBCOMP_ONLY_TEST_0()
    elif number == 8:
        return SUBSCRIBE_ONLY_TEST_0()
    elif number == 9:
        return SUBACK_ONLY_TEST_0()
    elif number == 10:
        return UNSUBSCRIBE_ONLY_TEST_0()
    elif number == 11:
        return UNSUBACK_ONLY_TEST_0()
    elif number == 12:
        return PINGREQ_ONLY_TEST_0()
    elif number == 13:
        return PINGRESP_ONLY_TEST_0()
    elif number == 14:
        return DISCONNECT_ONLY_TEST_1()
    elif number == 15:
        """
        TODO
        """
        return CONTROL_PACKET_TYPE.get(15)
    else:
        raise Exception(ERR_MESSAGE.get(0))


def CONNECT_ATTACK_EMU_1():
    """
    good
    :return:
    """
    round = 0
    while True:
        round += 1
        logging.debug(
            msg=f'ATTACK ROUND {round} START!'
        )
        temp_client_id = randomIP.RANDOM_NAME(suffix='MQTT_')
        temp_target_ip = '192.168.31.244'
        temp_target_port = 1883
        temp_src_ip = randomIP.IPV4()
        temp_src_port = random.randint(12000, 16665)
        topic = randomIP.RANDOM_NAME(suffix='python/', randomLen=random.randint(1, 10))
        value = randomIP.RANDOM_NAME(randomLen=random.randint(10, 20))

        send_scenarii(
            [
                build_mqtt_connect_packet_only(temp_client_id),
                SUBSCRIBE_ONLY_TEST_0(['python/#', 'test0']),
                PUBLISH_ONLY_TEST_0(topic=topic, value=value),
                # PUBLISH_ONLY_TEST_0(topic=topic, value=value),
                PUBLISH_ONLY_TEST_0(topic='test0', value=value),
                # PUBLISH_ONLY_TEST_0(topic='test0', value=value),
                UNSUBSCRIBE_ONLY_TEST_0(['python/#', 'test0']),
                # PUBLISH_ONLY_TEST_0(topic=topic, value=value),
                PUBLISH_ONLY_TEST_0(topic=topic, value=value),
                # PUBLISH_ONLY_TEST_0(topic=topic, value=value),
                # PUBLISH_ONLY_TEST_0(topic=topic, value=value),
                DISCONNECT_ONLY_TEST_1(),
                DISCONNECT_ONLY_TEST_1(),
                DISCONNECT_ONLY_TEST_1(),
                DISCONNECT_ONLY_TEST_1(),
                DISCONNECT_ONLY_TEST_1(),
                DISCONNECT_ONLY_TEST_1(),
                DISCONNECT_ONLY_TEST_1(),
                PINGREQ_ONLY_TEST_0(),
                PINGRESP_ONLY_TEST_0(),
                PINGREQ_ONLY_TEST_0(),
                PINGRESP_ONLY_TEST_0(),
                PINGREQ_ONLY_TEST_0(),
                PINGRESP_ONLY_TEST_0(),
                PINGREQ_ONLY_TEST_0(),
                PINGRESP_ONLY_TEST_0(),
                PINGREQ_ONLY_TEST_0(),
                PINGRESP_ONLY_TEST_0(),
            ],
            temp_target_ip)

        # time.sleep(1)
        break


if __name__ == '__main__':
    # CONNECT_TEST_0()
    # PUBLISH_TEST_0(destination=destination, topic=topic)
    # SOCKET_TEST_0()
    # CONNECT_ATTACK_EMU_0()
    CONNECT_ATTACK_EMU_1()
