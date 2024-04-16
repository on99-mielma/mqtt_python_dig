import json

import paho.mqtt.client as mqtt
import piconst as PC

BROKER = PC.BROKER
PORT = PC.PORT
TOPIC_SUB = PC.SUB_TOPIC
DOWN_TOPIC = PC.DOWN_TOPIC
UP_TOPIC = PC.UP_TOPIC
API_VERSION = mqtt.CallbackAPIVersion.VERSION2 if PC.API_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1
PROTOCOL = mqtt.MQTTv5
if PC.API_VERSION == 4:
    PROTOCOL = mqtt.MQTTv311
elif PC.API_VERSION == 3:
    PROTOCOL = mqtt.MQTTv31


def subscribe_callback_3(client, userdata, mid, granted_qos):
    """
    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param mid: matches the mid-variable returned from the corresponding to subscribe() call.
    :param granted_qos: list of integers that give the QoS level the broker has
                          granted for each of the different subscription requests.
    :return:
    """
    if granted_qos[0] is not None and isinstance(granted_qos[0], int) and 0 <= granted_qos[0] <= 2:
        userdata['qos'] = granted_qos[0]
    else:
        pass


def subscribe_callback_5(client, userdata, mid, reason_code_list, properties):
    """
    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param mid: matches the mid-variable returned from the corresponding to subscribe() call.
    :param reason_code_list: reason_code_list: reason codes received from the broker for each subscription.
                          In MQTT v5.0 it's the reason code defined by the standard.
                          In MQTT v3, we convert granted QoS to a reason code.
                          It's a list of ReasonCode instances.
    :param properties: the MQTT v5.0 properties received from the broker.
                          For MQTT v3.1 and v3.1.1 properties is not provided and an empty Properties
                          object is always used.
    :return:
    """
    s = reason_code_list[0].value
    if reason_code_list[0].is_failure:
        pass
    else:
        userdata['qos'] = s


def unsubscribe_callback_3(client, userdata, mid):
    """

    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param mid: matches the mid-variable returned from the corresponding
                          unsubscribe() call.
    :return:
    """
    client.disconnect()


def unsubscribe_callback_5(client, userdata, mid, properties, v1_reason_codes):
    """

    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param mid: matches the mid-variable returned from the corresponding
                          unsubscribe() call.
    :param properties: the MQTT v5.0 properties received from the broker.
                          For MQTT v3.1 and v3.1.1 properties is not provided and an empty Properties
                          object is always used.
    :param v1_reason_codes: the MQTT v5.0 reason codes received from the broker for each
                          unsubscribe topic.  A list of ReasonCode instances OR a single
                          ReasonCode when we unsubscribe from a single topic.
    :return:
    """
    client.disconnect()


def message_callback(client, userdata, message):
    """

    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param MQTTMessage message: the received message.
                    This is a class with members topic, payload, qos, retain.
    :return:
    """
    w = json.loads(message.payload.decode('utf-8'))
    print(w)
    data = w.get('code', None)
    mp = {}
    if data is None:
        pass
    elif data == 404:
        mp['state'] = 0
        json_data = json.dumps(mp)
        client.publish(topic=DOWN_TOPIC, payload=json_data, qos=userdata.get('qos', 0), retain=False)


def connect_callback_3(client, userdata, flags, rc):
    """

    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param ConnectFlags flags: the flags for this connection
    :param int rc: the connection result, should have a value of `ConnackCode`
    :return:
    """
    if rc == 0:
        client.subscribe(UP_TOPIC)
    else:
        pass


def connect_callback_5(client, userdata, flags, reason_code, properties):
    """

    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param dict flags: response flags sent by the broker
    :param ReasonCode reason_code: the connection reason code received from the broken.
                       In MQTT v5.0 it's the reason code defined by the standard.
                       In MQTT v3, we convert return code to a reason code, see
                       `convert_connack_rc_to_reason_code()`.
                       `ReasonCode` may be compared to integer.
    :param Properties properties:the MQTT v5.0 properties received from the broker.
                       For MQTT v3.1 and v3.1.1 properties is not provided and an empty Properties
                       object is always used.
    :return:
    """
    if reason_code.is_failure:
        print(f"<5>Failed to connect: {reason_code}. loop_forever() will retry connection")
    else:
        # we should always subscribe from on_connect callback to be sure
        # our subscribed is persisted across reconnections.
        client.subscribe(UP_TOPIC)


def publish_callback_5(client, userdata, mid, reason_code, properties):
    """
    发布回调函数，当消息成功发布时被调用（MQTTv5版本）
    """
    pass


def publish_callback_3(client, userdata, mid):
    """
    发布回调函数，当消息成功发布时被调用
    """
    pass


def control(api_version, target_broker, target_port, protocol):
    mqtt_client = mqtt.Client(callback_api_version=api_version, protocol=protocol)
    mqtt_client.on_publish = publish_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else publish_callback_3
    mqtt_client.on_connect = connect_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else connect_callback_3
    mqtt_client.on_message = message_callback
    mqtt_client.on_subscribe = subscribe_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else subscribe_callback_3
    mqtt_client.on_unsubscribe = unsubscribe_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else unsubscribe_callback_3
    qos_dist = {}
    mqtt_client.user_data_set(qos_dist)
    mqtt_client.connect(host=target_broker, port=target_port)
    mqtt_client.loop_forever()


if __name__ == '__main__':
    control(api_version=API_VERSION, target_broker=BROKER, target_port=PORT, protocol=PROTOCOL)
