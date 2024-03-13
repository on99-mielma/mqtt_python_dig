import codecs

from scapy.all import *
from scapy.layers.inet import TCP

import logging

logging.basicConfig(
    level=logging.NOTSET,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

packetList = []


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
        print(self.mqttType)
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
        newPacket = newPacket + self.mqttPacket.getHex()
        return " ".join(newPacket)


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
        self.messageWords = codecs.decode("".join(self.message), "hex")
        self.messageWords = codecs.decode(self.messageWords, "utf-8")
        if (len(mqtt) - self.messageLengthNum - 2) == 0:
            self.disconnect = False
        else:
            self.disconnect = True

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
        self.messageLengthNum = self.messageLengthNum - (self.messageLengthNum - len(newMessage))
        self.messageLength = hex(self.messageLengthNum)
        message = []
        for letter in newMessage:
            message.append(hex(ord(letter)))
        self.message = message

    def getHex(self):
        full = []
        meanings = {0: "10", 1: "20", 2: "82", 3: "90", 4: "30", 5: "c0", 6: "d0", 7: "31"}
        [full.append(meanings[int(x)]) for x in self.messageType]
        a = self.messageLength.replace("0x", "")
        if len(a) < 2:
            a = '0' + a
        full.append(a)
        # [full.append(x) for x in a]
        [full.append(x) for x in self.topicLength]
        [full.append(x) for x in self.topicName]
        [full.append(x.replace("0x", "")) for x in self.message]
        if self.disconnect == True:
            full.append("e0")
            full.append("00")
        return full


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


if __name__ == '__main__':
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
