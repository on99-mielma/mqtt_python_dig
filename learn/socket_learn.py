
# s = socket.socket()
#
# s.bind(('192.168.31.233', 16666))
# s.listen()
# times = 0
# SUMM = 1e9
# while True:
#     c, addr = s.accept()
#     print('>' * 64)
#     print(c)
#     print('addr = ', addr)
#     print('<' * 64)
#     times += 1
#     if times >= SUMM:
#         break
# c.close()
from scapy.all import *
from scapy.contrib.mqtt import MQTT, MQTTConnect, MQTTPublish
from scapy.layers.inet import TCP

import CONST

# 建立TCP连接
target_ip = CONST.IP_ADDRESS
client_id = "socket_scapy_test"
target_port = CONST.DST_PORT
source_ip = "192.168.31.233"
src_port = RandShort()
BUFFSIZE = 2048
TOPIC = 'python/fucku'
VALUE = '01234567899876543210'


# ADDRESS = (target_ip, target_port)


def build_mqtt_connect_packet(client_id, destination, source, target_port, src_port):
    tcp = TCP(dport=target_port, sport=src_port)
    tcp.flags = 'A'
    tcp.flags |= 'P'
    diy = bytes([0x5, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, len(client_id)])
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
    print('*' * 100)
    packet.show()
    print('*' * 100)
    return packet


def PUBLISH_TEST_0(topic, value):
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
    print('*' * 100)
    package.show()
    print('*' * 100)
    return package


def MAKE_SOCKET_0(target_ip, target_port, src_port):
    # syn_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
    # syn_ack_response = sr1(syn_packet)
    #
    # # 提取目标IP和目标端口
    # target_ip = syn_ack_response[IP].src
    # target_port = syn_ack_response[TCP].sport

    # 建立套接字连接
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.connect((target_ip, target_port))
    pd0 = 0
    count = 0
    # 发送数据
    while True:
        if pd0 == 0:
            sock.send(
                bytes(build_mqtt_connect_packet(client_id=client_id, destination=target_ip, source=source_ip,
                                                target_port=target_port,
                                                src_port=src_port)))
            pd0 += 1
            print('CONNECT COMMAND DONE')
        elif pd0 == 1:
            sock.send(
                bytes(PUBLISH_TEST_0(topic=TOPIC, value=VALUE))
            )
            pd0 += 1
            print('PUBLISH QOS0 DONE')
        packet_recv = sock.recv(2048)
        if not packet_recv:
            print('NOTHING')
        else:
            print(f'receive >> {packet_recv}')
        count += 1
        if count > 1e9:
            break
        time.sleep(1)
    # 关闭套接字连接
    sock.close()


if __name__ == '__main__':
    MAKE_SOCKET_0(target_ip=target_ip, target_port=target_port, src_port=src_port)
