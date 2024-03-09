from paho.mqtt import client as mqtt_client
import datetime
import pytz

broker = '192.168.31.244'
port = 1883
topic = 'python/q'
client_id = 'python-mqtt-746933945'


def connect_mqtt() -> mqtt_client:
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("成功连接到MQTT服务器")
        else:
            print("连接MQTT服务器失败，错误代码是:: %d", rc)

    client = mqtt_client.Client(client_id=client_id)
    client.on_connect = on_connect
    client.connect(host=broker, port=port)
    return client


def subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        datetime_in_china = datetime.datetime.now(pytz.timezone('Asia/Shanghai'))
        print(
            f"\n接收时间为{datetime_in_china}\n 接收到消息为：\n\n {msg.payload.decode()} \n\n 主题来自于： {msg.topic}")
        print("DEBUG_TIME::CLASS_MESSAGE \n{}".format(msg))
        print("DEBUG_TIME::timestamp \n{}".format(msg.timestamp))
        print("DEBUG_TIME::state \n{}".format(msg.state))
        print("DEBUG_TIME::dup \n{}".format(msg.dup))
        print("DEBUG_TIME::mid \n{}".format(msg.mid))
        print("DEBUG_TIME::topic \n{}".format(msg.topic))
        print("DEBUG_TIME::payload_without_decode \n{}".format(msg.payload))
        print("DEBUG_TIME::qos \n{}".format(msg.qos))
        print("DEBUG_TIME::retain \n{}".format(msg.retain))
        print("DEBUG_TIME::info \n{}".format(msg.info))

    client.subscribe(topic)
    client.on_message = on_message


def run():
    client = connect_mqtt()
    subscribe(client)
    client.loop_forever()


if __name__ == '__main__':
    run()
