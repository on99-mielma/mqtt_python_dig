import time
import psutil
import datetime
import random
import json
import paho.mqtt.publish as publish
import paho.mqtt.client as mqtt

PD = True


def on_message_print(client, userdata, message):
    global PD
    w = json.loads(message.payload.decode('utf-8'))
    data = w.get('state', None)
    if data is None:
        pass
    elif data == 0:
        print(f'GET THE STATE OF {data} NOW PROGRAM WILL SHUTDOWN')
        PD = False
    client.disconnect()


def logical_count():
    return f'CPU LOGICAL COUNT := <{psutil.cpu_count()}>'


def physics_count():
    return f'CPU PHYSICS COUNT := <{psutil.cpu_count(logical=False)}>'


def cpu_user_system_free_time():
    return psutil.cpu_times()


def cpu_used_percent():
    """
    stop 1 second
    useless
    :return:
    """
    return psutil.cpu_percent(1)


def memory_all():
    return psutil.virtual_memory()


def total_memory_GB():
    mem = psutil.virtual_memory()
    return float(mem.total) / 1024 / 1024 / 1024


def total_memory_MB():
    mem = psutil.virtual_memory()
    return float(mem.total) / 1024 / 1024


def available_memory_GB():
    mem = psutil.virtual_memory()
    return float(mem.free) / 1024 / 1024 / 1024


def available_memory_MB():
    mem = psutil.virtual_memory()
    return float(mem.free) / 1024 / 1024


def format_datetime_now():
    # 获取当前时间
    current_time = datetime.datetime.now()
    # 格式化当前时间
    formatted_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    return formatted_time


def random_code():
    return random.randint(100, 599)


def gen_data_json():
    mp = {}
    mp['code'] = random_code()
    mp['time'] = format_datetime_now()
    mp['cpu_logical'] = psutil.cpu_count()
    mp['available_mem_MB'] = available_memory_MB()
    json_data = json.dumps(mp)
    # print(json_data)
    return json_data


def mqtt_publish_json():
    import piconst as PC
    publish.single(
        topic=PC.UP_TOPIC,
        payload=gen_data_json(),
        qos=PC.QOS,
        hostname=PC.BROKER,
        port=PC.PORT,
        protocol=mqtt.MQTTv5 if PC.API_VERSION == 5 else mqtt.MQTTv311,
    )


def print_cpu_mem():
    print('=' * 64)
    print(logical_count())
    print(physics_count())
    print(f'CPU TIME STATE := <{cpu_user_system_free_time()}>')
    # print(f'CPU PERCENT STATE := <{cpu_used_percent()}>')
    print(f'MEMORY STATE := <{memory_all()}>')
    print(f'TOTAL MEMORY STATE := <{total_memory_GB()} GB>')
    print(f'TOTAL MEMORY STATE := <{total_memory_MB()} MB>')
    print(f'AVAILABLE MEMORY STATE := <{available_memory_GB()} GB>')
    print(f'AVAILABLE MEMORY STATE := <{available_memory_MB()} MB>')
    print(f'CURRENT TIME  STATE := <{format_datetime_now()}>')
    print(f'RANDOM CODE := <{random_code()}>')
    data = gen_data_json()
    print(data)
    print('=' * 64)


if __name__ == '__main__':
    import piconst as PC

    API_VERSION = mqtt.CallbackAPIVersion.VERSION2 if PC.API_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1
    PROTOCOL = mqtt.MQTTv5
    if PC.API_VERSION == 4:
        PROTOCOL = mqtt.MQTTv311
    elif PC.API_VERSION == 3:
        PROTOCOL = mqtt.MQTTv31
    mqttc = mqtt.Client(callback_api_version=API_VERSION, protocol=PROTOCOL)
    mqttc.on_message = on_message_print
    mqttc.connect(PC.BROKER, PC.PORT)
    mqttc.subscribe(topic=PC.DOWN_TOPIC, qos=PC.QOS)
    print_cpu_mem()
    while PD:
        mqtt_publish_json()
        time.sleep(1)
        mqttc.loop(timeout=1)
