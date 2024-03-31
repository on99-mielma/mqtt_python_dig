import codecs

from scapy.contrib.mqtt import MQTT
from scapy.utils import rdpcap

GLOBAL_VERSION = 5

ERROR_MESSAGE = {
    0: 'SCAPY_SUSPECT',
    1: 'BRUTE_SUSPECT',
}


class MQTTPackage:

    def __init__(self, packet) -> None:
        """
        有点假设一次tcp报文中只有一次mqtt信息
        实际上可能不止如此
        we must promise "packet" has MQTT layer else we raise Exception
        :param packet: scapy packet
        """
        try:
            self.suspect = 0
            get_mqtt_out = packet[MQTT]
            if get_mqtt_out.payload is None:
                self.suspect += 1
                raise Exception("suspect")
            self.type = int(get_mqtt_out.type)
            self.dup = get_mqtt_out.DUP
            self.qos = get_mqtt_out.QOS
            self.retain = get_mqtt_out.RETAIN
            self.len = get_mqtt_out.len
            self.time = get_mqtt_out.time
            self.name = get_mqtt_out.name
            self.original = get_mqtt_out.original
            self.subPackageFlag = False
            if get_mqtt_out.payload.haslayer(MQTT):
                self.suspect += 1
                self.subPackageFlag = True
                self.subPackage = MQTTPackage(get_mqtt_out.payload[MQTT])
            if self.type == 1:
                self.subMQTTPackage = MQTTConnect(get_mqtt_out.payload)
            elif self.type == 2:
                self.subMQTTPackage = MQTTConnectAck(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 3:
                self.subMQTTPackage = MQTTPublish(get_mqtt_out.payload, version=GLOBAL_VERSION, qos=self.qos)
            elif self.type == 4:
                self.subMQTTPackage = MQTTPublishAck(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 5:
                self.subMQTTPackage = MQTTReceived(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 6:
                self.subMQTTPackage = MQTTRelease(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 7:
                self.subMQTTPackage = MQTTComplete(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 8:
                self.subMQTTPackage = MQTTSubscribe(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 9:
                self.subMQTTPackage = MQTTSubscribeAck(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 10:
                self.subMQTTPackage = MQTTUnsubscribe(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 11:
                self.subMQTTPackage = MQTTUnsubscribeAck(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 12:
                self.subMQTTPackage = MQTTPingRequest(get_mqtt_out)
            elif self.type == 13:
                self.subMQTTPackage = MQTTPingResponse(get_mqtt_out.payload)
            elif self.type == 14:
                self.subMQTTPackage = MQTTDisconnect(get_mqtt_out.payload, version=GLOBAL_VERSION)
            elif self.type == 15:
                self.subMQTTPackage = MQTTAuthentication(get_mqtt_out.payload)
            else:
                self.subMQTTPackage = None
                self.suspect += 1
        except AttributeError as ae:
            self.suspect += 1
            print(ae)
        except Exception as e:
            self.suspect += 1
            print(e)

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTConnect:
    def __init__(self, packet) -> None:
        """
        we must promise "packet" has MQTTConnect layer else we raise Exception
        :param packet: MQTTConnect
        """
        try:
            self.cleansess = packet.cleansess
            self.length = packet.length
            self.protoname = packet.protoname
            self.protolevel = packet.protolevel
            global GLOBAL_VERSION
            GLOBAL_VERSION = self.protolevel
            self.usernameflag = packet.usernameflag
            self.passwordflag = packet.passwordflag
            self.willretainflag = packet.willretainflag
            self.willQOSflag = packet.willQOSflag
            self.willflag = packet.willflag
            self.reserved = packet.reserved
            self.klive = packet.klive
            self.clientIdlen = packet.clientIdlen
            self.clientId = packet.clientId

            self.time = packet.time
            self.original = packet.original

            if GLOBAL_VERSION == 5:
                temp_hexstrlist = original_to_hexval(self.original)
                self.protocolNameLength = hexToInt(temp_hexstrlist[0:2])
                if self.protocolNameLength >= len(temp_hexstrlist):
                    raise Exception(ERROR_MESSAGE.get(0))
                self.protocolName = temp_hexstrlist[2:2 + self.protocolNameLength]
                self.version = hexToInt(temp_hexstrlist[2 + self.protocolNameLength:3 + self.protocolNameLength])
                self.connectFlags = hexToInt(temp_hexstrlist[3 + self.protocolNameLength:4 + self.protocolNameLength])
                self.keepAlive = hexToInt(temp_hexstrlist[4 + self.protocolNameLength:6 + self.protocolNameLength])
                self.propertiesLength = hexToInt(
                    temp_hexstrlist[6 + self.protocolNameLength:7 + self.protocolNameLength])
                if self.propertiesLength >= len(temp_hexstrlist):
                    raise Exception(ERROR_MESSAGE.get(0))
                self.properties = temp_hexstrlist[
                                  7 + self.protocolNameLength:7 + self.propertiesLength + self.protocolNameLength]
                self.clientIdLength = hexToInt(temp_hexstrlist[
                                               7 + self.propertiesLength + self.protocolNameLength:9 + self.propertiesLength + self.protocolNameLength])
                if self.clientIdLength >= len(temp_hexstrlist):
                    raise Exception(ERROR_MESSAGE.get(0))
                self.clientId = temp_hexstrlist[
                                9 + self.propertiesLength + self.protocolNameLength:9 + self.propertiesLength + self.protocolNameLength + self.clientIdLength]
                self.clientIdWords = codecs.decode("".join(self.clientId), "hex")
                self.clientIdWords = codecs.decode(self.clientIdWords, "utf-8")
                self.willPropertiesLength = 0
                self.willBackupLength0 = 0
                self.willBackupLength1 = 0
                self.willBackupLength2 = 0
                self.userNameBackupLength = 0
                self.passwordBackupLength = 0
                self.willProperties = None
                self.willTopicLength = 0
                self.willTopic = None
                self.willMessageLength = 0
                self.willMessage = None
                self.userNameLength = 0
                self.userName = None
                self.passwordLength = 0
                self.password = None
                if self.willflag == 1:
                    self.willBackupLength0 = 1
                    self.willBackupLength1 = 2
                    self.willBackupLength2 = 2
                    self.willPropertiesLength = hexToInt(
                        temp_hexstrlist[
                        9 + self.propertiesLength + self.protocolNameLength + self.clientIdLength
                        :
                        9 + self.willBackupLength0 + self.propertiesLength + self.protocolNameLength + self.clientIdLength])
                    self.willProperties = temp_hexstrlist[
                                          9 + self.willBackupLength0 + self.propertiesLength + self.protocolNameLength + self.clientIdLength:
                                          9 + self.willBackupLength0 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength
                                          ]
                    self.willTopicLength = hexToInt(
                        temp_hexstrlist[
                        9 + self.willBackupLength0 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength
                        :
                        9 + self.willBackupLength0 + self.willBackupLength1 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength]
                    )
                    self.willTopic = temp_hexstrlist[
                                     9 + self.willBackupLength0 + self.willBackupLength1 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength
                                     :
                                     9 + self.willBackupLength0 + self.willBackupLength1 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength
                                     ]
                    self.willTopicWords = codecs.decode("".join(self.willTopic), "hex")
                    self.willTopicWords = codecs.decode(self.willTopicWords, "utf-8")
                    self.willMessageLength = hexToInt(
                        temp_hexstrlist[
                        9 + self.willBackupLength0 + self.willBackupLength1 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength
                        :
                        9 + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength
                        ]
                    )
                    self.willMessage = temp_hexstrlist[
                                       9 + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength
                                       :
                                       9 + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength + self.willMessageLength
                                       ]
                    self.willMessageWords = codecs.decode("".join(self.willMessage), "hex")
                    self.willMessageWords = codecs.decode(self.willMessageWords, "utf-8")
                if self.usernameflag == 1:
                    self.userNameBackupLength = 2
                    self.userNameLength = hexToInt(
                        temp_hexstrlist[
                        9 + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength + self.willMessageLength
                        :
                        9 + self.userNameBackupLength + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength + self.willMessageLength
                        ]
                    )
                    self.userName = temp_hexstrlist[
                        9 + self.userNameBackupLength + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength + self.willMessageLength + self.userNameLength
                        ]
                    self.userNameWords = codecs.decode("".join(self.userName), "hex")
                    self.userNameWords = codecs.decode(self.userNameWords, "utf-8")
                if self.passwordflag == 1:
                    self.passwordBackupLength = 2
                    self.passwordLength = hexToInt(
                        temp_hexstrlist[
                        9 + self.userNameBackupLength + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength + self.willMessageLength + self.userNameLength
                        :
                        9 + self.passwordBackupLength + self.userNameBackupLength + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength + self.willMessageLength + self.userNameLength
                        ]
                    )
                    self.password = temp_hexstrlist[
                                    9 + self.passwordBackupLength + self.userNameBackupLength + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength + self.willMessageLength + self.userNameLength
                                    :
                                    9 + self.passwordBackupLength + self.userNameBackupLength + self.willBackupLength0 + self.willBackupLength1 + self.willBackupLength2 + self.propertiesLength + self.protocolNameLength + self.clientIdLength + self.willPropertiesLength + self.willTopicLength + self.willMessageLength + self.userNameLength + self.passwordLength
                                    ]
                    self.passwordWords = codecs.decode("".join(self.password), "hex")
                    self.passwordWords = codecs.decode(self.passwordWords, "utf-8")

            else:
                if self.passwordflag is not None and self.passwordflag == 1:
                    self.passlen = packet.passlen
                    self.password = packet.password

                if self.usernameflag is not None and self.usernameflag == 1:
                    self.userlen = packet.userlen
                    self.username = packet.username

                if self.willflag is not None and self.willflag == 1:
                    self.wtoplen = packet.wtoplen
                    self.willtopic = packet.willtopic
                    self.wmsglen = packet.wmsglen
                    self.willmsg = packet.willmsg

        except AttributeError as ae:
            print(ae)
        except Exception as e:
            print(e)

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTSubscribe:
    def __init__(self, packet, version=5) -> None:
        """
        we must promise "packet" has MQTTSubscribe layer else we raise Exception
        remember scapy cannot deal with mqtt5 subscribe
        :param packet: MQTTSubscribe
        """
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            self.msgid = packet.msgid
            self.name = packet.name
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid2 = hexToInt(temp_hexstrlist[0:2])
            self.propertiesLength = hexToInt(temp_hexstrlist[2:3])
            self.properties = temp_hexstrlist[3:3 + self.propertiesLength]
            self.topicLength = hexToInt(temp_hexstrlist[3 + self.propertiesLength:5 + self.propertiesLength])
            self.topic = temp_hexstrlist[5 + self.propertiesLength:5 + self.propertiesLength + self.topicLength]
            self.topicWords = codecs.decode("".join(self.topic), "hex")
            self.topicWords = codecs.decode(self.topicWords, "utf-8")
            self.subscriptionOptions = temp_hexstrlist[5 + self.propertiesLength + self.topicLength:]
        else:
            self.msgid = packet.msgid
            self.topics = packet.topics
            self.topicList = []
            self.topicLengthList = []
            self.qosList = []
            for t in self.topics:
                self.topicList.append(t.topic)
                self.topicLengthList.append(t.length)
                self.qosList.append(t.QOS)

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTConnectAck:

    def __init__(self, packet, version=5) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.sessPresentFlag = packet.sessPresentFlag
            self.retcode = packet.retcode
            self.acknowledgeFlags = temp_hexstrlist[0:1]  # 7bit reserved 1bit session present
            self.reasonCode = hexToInt(temp_hexstrlist[1:2])
            self.propertiesLength = hexToInt(temp_hexstrlist[2:3])
            if self.propertiesLength > 0:
                self.properties = temp_hexstrlist[3:3 + self.propertiesLength]
            else:
                self.properties = None
        else:
            self.sessPresentFlag = packet.sessPresentFlag
            self.retcode = packet.retcode

    def __str__(self) -> str:
        return str(vars(self))


class MQTTSubscribeAck:

    def __init__(self, packet, version=5) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid = hexToInt(temp_hexstrlist[0:2])
            self.propertiesLength = hexToInt(temp_hexstrlist[2:3])
            self.properties = temp_hexstrlist[3:3 + self.propertiesLength]
            self.reasonCode = hexToInt(temp_hexstrlist[3 + self.propertiesLength:4 + self.propertiesLength])

        else:
            self.msgid = packet.msgid
            self.retcode = packet.retcode

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTPublish:

    def __init__(self, packet, version=5, qos=0) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid_len = 0 if qos == 0 else 2
            self.topicLength = hexToInt(temp_hexstrlist[0:2])
            self.topic = temp_hexstrlist[2:2 + self.topicLength]
            self.msgid = hexToInt(temp_hexstrlist[2 + self.topicLength:2 + self.topicLength + self.msgid_len])
            self.propertiesLength = hexToInt(
                temp_hexstrlist[2 + self.topicLength + self.msgid_len:3 + self.topicLength + self.msgid_len])
            self.properties = temp_hexstrlist[
                              3 + self.topicLength + self.msgid_len:3 + self.topicLength + self.msgid_len + self.propertiesLength]
            self.message = temp_hexstrlist[
                           3 + self.topicLength + self.msgid_len + self.propertiesLength:
                           ]
            self.topicWords = codecs.decode("".join(self.topic), "hex")
            self.topicWords = codecs.decode(self.topicWords, "utf-8")
            self.messageWords = codecs.decode("".join(self.message), "hex")
            self.messageWords = codecs.decode(self.messageWords, "utf-8")

        else:
            self.length = packet.length
            self.topic = packet.topic
            self.msgid = packet.msgid
            self.value = packet.value

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTPublishAck:

    def __init__(self, packet, version=5) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid = hexToInt(temp_hexstrlist[0:2])
            self.reasonCode = hexToInt(temp_hexstrlist[2:3])
            self.propertiesLength = hexToInt(temp_hexstrlist[3:4])
            if self.propertiesLength > 0:
                self.properties = temp_hexstrlist[4:4 + self.propertiesLength]
            else:
                self.properties = None
        else:
            self.msgid = packet.msgid

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTDisconnect:

    def __init__(self, packet, version=5) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.reasonCode = hexToInt(temp_hexstrlist[0:1])
            self.propertiesLength = hexToInt(temp_hexstrlist[1:2])
            if self.propertiesLength > 0:
                self.properties = temp_hexstrlist[2:2 + self.propertiesLength]
            else:
                self.properties = None

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTReceived:

    def __init__(self, packet, version=5) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid = hexToInt(temp_hexstrlist[0:2])
            self.reasonCode = hexToInt(temp_hexstrlist[2:3])
            self.propertiesLength = hexToInt(temp_hexstrlist[3:4])
            if self.propertiesLength > 0:
                self.properties = temp_hexstrlist[4:4 + self.propertiesLength]
            else:
                self.properties = None
        else:
            self.msgid = packet.msgid

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTRelease:

    def __init__(self, packet, version=5) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid = hexToInt(temp_hexstrlist[0:2])
            self.reasonCode = hexToInt(temp_hexstrlist[2:3])
        else:
            self.msgid = packet.msgid

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTComplete:

    def __init__(self, packet, version=5) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid = hexToInt(temp_hexstrlist[0:2])
            self.reasonCode = hexToInt(temp_hexstrlist[2:3])
            self.propertiesLength = hexToInt(temp_hexstrlist[3:4])
            if self.propertiesLength > 0:
                self.properties = temp_hexstrlist[4:4 + self.propertiesLength]
            else:
                self.properties = None
        else:
            self.msgid = packet.msgid

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTUnsubscribe:
    def __init__(self, packet, version=5) -> None:
        """
        we must promise "packet" has MQTTUnsubscribe layer else we raise Exception
        :param packet: MQTTUnsubscribe
        """
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid = hexToInt(temp_hexstrlist[0:2])
            self.propertiesLength = hexToInt(temp_hexstrlist[2:3])
            self.properties = temp_hexstrlist[3:3 + self.propertiesLength]
            self.topicLength = hexToInt(temp_hexstrlist[3 + self.propertiesLength:5 + self.propertiesLength])
            self.topic = temp_hexstrlist[5 + self.propertiesLength:5 + self.propertiesLength + self.topicLength]
            self.topicWords = codecs.decode("".join(self.topic), "hex")
            self.topicWords = codecs.decode(self.topicWords, "utf-8")
        else:
            self.msgid = packet.msgid
            self.topics = packet.topics
            self.topicList = []
            self.topicLengthList = []
            for t in self.topics:
                self.topicList.append(t.topic)
                self.topicLengthList.append(t.length)

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTUnsubscribeAck:

    def __init__(self, packet, version=5) -> None:
        self.time = packet.time
        self.original = packet.original
        self.version = version
        if version == 5:
            temp_hexstrlist = original_to_hexval(self.original)
            self.msgid = hexToInt(temp_hexstrlist[0:2])
            self.propertiesLength = hexToInt(temp_hexstrlist[2:3])
            self.properties = temp_hexstrlist[3:3 + self.propertiesLength]
            self.reasonCode = hexToInt(temp_hexstrlist[3 + self.propertiesLength:4 + self.propertiesLength])

        else:
            self.msgid = packet.msgid

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTPingRequest:

    def __init__(self, packet) -> None:
        """
        ping request has nothing
        :param packet: MQTT HEADER
        """
        self.time = packet.time
        self.original = packet.original

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTPingResponse:

    def __init__(self, packet) -> None:
        """
        ping response has nothing but there are 'bytes(4)' there
        :param packet:
        """
        self.time = packet.time
        self.original = packet.original

    def __str__(self) -> str:
        return str(vars(self))

    def __repr__(self) -> str:
        return str(vars(self))


class MQTTAuthentication:

    def __init__(self, packet) -> None:
        self.time = packet.time
        self.original = packet.original
        temp_hexstrlist = original_to_hexval(self.original)
        self.reasonCode = hexToInt(temp_hexstrlist[0:1])
        self.propertiesLength = hexToInt(temp_hexstrlist[1:2])
        self.properties = temp_hexstrlist[2:2 + self.propertiesLength]

    def __str__(self) -> str:
        return str(vars(self))


def original_to_hexval(byteses):
    return [format(byte, '02x') for byte in byteses]


def hexToInt(hexstrlist):
    try:
        if len(hexstrlist) == 0:
            return None
        return int("".join(hexstrlist), 16)
    except Exception as e:
        print(e)
        return None


def analyze_bytes(hexstrlist, mode):
    pass


if __name__ == '__main__':
    packages = rdpcap('pcap/connectcommand.pcap')
    list0 = []
    list1 = []
    for p in packages:
        list0.append(p)
        list1.append(MQTTPackage(p))
    for l1 in list1:
        print(l1, end='\n\n\n')

    """
    def GEN_RANDOM_PACKAGE_PUBLISH_MAIN():
        mqtt_type = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        choose_type = random.choices(mqtt_type, [1, 1, 1, 1, 1, 1, 1, 1, 1, 999, 1, 1, 1, 1, 1])
        return choose_type[0]
    import learn.scapy_learn as lsl
    # 自己做的包不发出去是不会有original字段的
    for i in range(5):
        tempp = lsl.GEN_RANDOM_PACKAGE_EQUAL(
            number=GEN_RANDOM_PACKAGE_PUBLISH_MAIN(),
            clientId_suffix='MQTT_',
            topic_suffix='test/',
            topicName='test/#')
        pack = MQTTPackage(tempp)
        print(f'no.{i} TEST STRING = <{pack}>')
    """
