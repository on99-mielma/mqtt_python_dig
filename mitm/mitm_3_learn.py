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
    allHex = []
    cleanPacket = str(raw(packet))[2:-1] # this step can remove <b''>
    splitPacket = cleanPacket.split("\\")
    for a in splitPacket:
        # print("________________" + a + "_____________")
        reg = re.findall(r"[xX][0-9a-fA-F]{2}", a)
        if reg:
            allHex.append(reg[0].replace("x", ""))
            leftOver = a.replace(reg[0], "")
            # c = codecs.encode(b, "hex")
            # print(reg)
            newHex = charToHex(leftOver)
            for n in newHex:
                allHex.append(n.replace("0x", ""))
        else:
            newHex = charToHex(a)
            for n in newHex:
                allHex.append(n.replace("0x", ""))
        # print(allHex)
    return (allHex)


class TcpPacket:
    def __init__(self, packet):  # here packet should be a list of hex values
        self.entirePacket = packet
        self.destination = packet[:6]  # first six bytes
        self.source = packet[6:12]  # next six bytes
        self.coreProtocol = packet[12:14]  # next 2 bytes
        self.ipVersion = packet[14:34]  # next 20 bytes are ipv4 stuff
        self.tcp = packet[34:66]  # next 32 bytes defines TCP protocol
        self.mqtt = packet[66:]

        self.mqttType = self.typeMap(self.mqtt[0])
        print(self.mqttType)
        if self.mqttType[0] == 4 or self.mqttType[0] == 7:
            self.mqttPacket = MqttPublish(self.mqtt)
        else:
            self.mqttPacket = None  # rest of packet will be MQTT

    def typeMap(self, hexVal):
        meanings = {"10": 0, "20": 1, "82": 2, "90": 3, "30": 4, "c0": 5, "d0": 6, "31": 7}
        hexToCommand = {0: "Connect Command", 1: "Connect Ack", 2: "Suscribe Request", 3: "Suscribe Ack",
                        4: "Publisher Message", 5: "Ping Request", 6: "Ping Response", 7: "Publisher Message (Retain)"}
        a = meanings[hexVal]
        b = hexToCommand[a]
        return (a, b)

    def rebuildPacket(self):
        newPacket = self.entirePacket[:66]
        newPacket = newPacket + self.mqttPacket.getHex()
        return " ".join(newPacket)


# class for the mqtt Connect Command
class MqttPublish:
    def __init__(self, mqtt):
        self.entirePacket = mqtt
        code, word = self.typeMap(mqtt[0])
        self.messageType = mqtt[0]
        self.messageTypeWord = word
        self.messageLength = mqtt[1]
        self.messageLengthNum = self.hexToInt(self.messageLength)
        self.topicLength = mqtt[2:4]
        self.topicLengthNum = self.hexToInt(self.topicLength)
        self.topicName = self.findTopicName(self.topicLength, mqtt)
        self.message = mqtt[self.topicLengthNum + 4:][:self.messageLengthNum - self.topicLengthNum - 3]
        self.messageWords = codecs.decode("".join(self.message), "hex")
        self.messageWords = codecs.decode(self.messageWords, "utf-8")
        if (len(packetList[8][66:]) - self.messageLengthNum - 2) == 0:
            self.disconnect = False
        else:
            self.disconnect = True

    def findTopicName(self, topicLength, mqtt):
        length = self.hexToInt(topicLength)  # convert hex string to int
        topicName = mqtt[4:length + 4]
        return (topicName)

    def hexToInt(self, length):
        return (int("".join(length), 16))

    def typeMap(self, hexVal):
        meanings = {"10": 0, "20": 1, "82": 2, "90": 3, "30": 4, "c0": 5, "d0": 6, "31": 7}
        hexToCommand = {0: "Connect Command", 1: "Connect Ack", 2: "Suscribe Request", 3: "Suscribe Ack",
                        4: "Publisher Message", 5: "Ping Request", 6: "Ping Response", 7: "Publisher Message (Retain)"}
        a = meanings[hexVal]
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
        return (full)


def onlyMQTTPackets(packets):
    processedPackets = []
    for packet in packets:
        processedPackets.append(TcpPacket(packet))

    messageRequests = []
    for pPacket in processedPackets:
        num, word = pPacket.mqttType
        if num == 4 or num == 7:
            messageRequests.append(pPacket)
    return (messageRequests)

if __name__ == '__main__':
    packages = analysis_pcap('./mqtt_packets_tcpdump_3.pcap')

    # rawlist = []
    # for p in packages:
    #     print(str(raw(p))) # this can replace str

    tcp_packages = seek_tcp_package(packages=packages)
    for tp in tcp_packages:
        packetList.append(fixHex(tp))
    print(packetList)
    msg_packages = onlyMQTTPackets(packetList)
    print(msg_packages)
