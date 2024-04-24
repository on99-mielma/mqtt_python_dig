import random
import time
from collections import deque
import logging
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
from paho.mqtt.enums import MQTTProtocolVersion

import CONST
from learn import randomIP

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
BROKER = CONST.IP_ADDRESS
PORT = CONST.DST_PORT
API_VERSION = mqtt.CallbackAPIVersion.VERSION2 if CONST.BIG_MQTT_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1
TOPIC_SUFFIX = CONST.PUBLISH_TOPIC_SUFFIX


def publish_callback_5(client, userdata, mid, reason_code, properties):
    """
    发布回调函数，当消息成功发布时被调用（MQTTv5版本）
    """
    logging.debug(
        msg=f'userdata = <{userdata}>'
    )
    userdata.discard(mid)


def publish_callback_3(client, userdata, mid):
    """
    发布回调函数，当消息成功发布时被调用
    """
    logging.debug(
        msg=f'userdata = <{userdata}>'
    )
    userdata.discard(mid)


def gen_messages_tuple(topic_suffix, msgs_len=800, retain_flag=False):
    msgs_list = [('', '', 0, retain_flag)] * msgs_len
    for i in range(msgs_len):
        topic = randomIP.RANDOM_NAME(suffix=topic_suffix, randomLen=4)
        message = randomIP.RANDOM_JSON(key_len=random.randint(1, 4))
        qos = random.randint(0, 2)
        retain = retain_flag
        msgs_list[i] = (topic, message, qos, retain)
    logging.debug(
        msg=f'messages_list = <{msgs_list}>'
    )
    return msgs_list


def run_with_client(topic_suffix, api_version, target_broker, target_port, msgs_len=100, retain_flag=False):
    unacked_publish = set()
    mqtt_client = mqtt.Client(callback_api_version=api_version, client_id=randomIP.RANDOM_NAME(), clean_session=True)
    mqtt_client.on_publish = publish_callback_5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else publish_callback_3
    mqtt_client.user_data_set(unacked_publish)
    mqtt_client.connect(host=target_broker, port=target_port)
    mqtt_client.subscribe(topic=TOPIC_SUFFIX + '#')
    mqtt_client.loop_start()
    msg_deque = deque()
    for _ in range(msgs_len):
        topic = randomIP.RANDOM_NAME(suffix=topic_suffix, randomLen=4)
        message = randomIP.RANDOM_JSON(key_len=random.randint(1, 4))
        qos = random.randint(0, 2)
        msg_info = mqtt_client.publish(topic=topic, payload=message, qos=qos, retain=retain_flag)
        unacked_publish.add(msg_info.mid)
        msg_deque.append(msg_info)
    prelen, nowlen = -1, 1
    while len(unacked_publish):
        if prelen == nowlen:
            break
        else:
            prelen = nowlen
            nowlen = len(unacked_publish)
        time.sleep(0.1)
    if mqtt_client.is_connected():
        mqtt_client.disconnect()
        mqtt_client.loop_stop()
    return len(unacked_publish)


def mad_lion(target_broker, target_port, api_version, ez_flag=True):
    logging.info(
        msg=f'RUN MAD LION WITH <{"EZ MODE" if ez_flag else "NONE EZ MODE"}>'
    )
    start_time = time.time()
    if ez_flag:
        msgs = gen_messages_tuple(topic_suffix=TOPIC_SUFFIX)
        logging.info(
            msg=f'GENERATED <{len(msgs)}> MESSAGES, PUBLISH START SOON'
        )
        publish.multiple(
            msgs=msgs,
            hostname=target_broker,
            protocol=MQTTProtocolVersion.MQTTv5 if api_version == mqtt.CallbackAPIVersion.VERSION2 else MQTTProtocolVersion.MQTTv311,
            port=target_port,
            client_id=randomIP.RANDOM_NAME()
        )
        end_time = time.time()
        logging.info(
            msg=f'PUBLISHED <{len(msgs)}> MESSAGES, COST <{end_time - start_time}> SECONDS'
        )
    else:
        MSG_LEN = 1000
        logging.info(
            msg=f'GENERATED <{MSG_LEN}> MESSAGES, PUBLISH START SOON'
        )
        left_len = run_with_client(
            topic_suffix=TOPIC_SUFFIX,
            api_version=api_version,
            target_broker=target_broker,
            target_port=target_port,
            msgs_len=MSG_LEN
        )
        end_time = time.time()
        logging.info(
            msg=f'PUBLISHED <{MSG_LEN - left_len}> MESSAGES, COST <{end_time - start_time}> SECONDS'
        )


def show_mad_lion(broker, port, api_version, ezflag):
    while True:
        mad_lion(
            target_broker=broker,
            target_port=port,
            api_version=api_version,
            ez_flag=ezflag
        )


if __name__ == '__main__':
    show_mad_lion(BROKER, PORT, API_VERSION, False)
