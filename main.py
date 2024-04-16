import paho.mqtt.client as mqtt

import CONST
import argparse

IP_ADDRESS = CONST.IP_ADDRESS
# CONST.IP_ADDRESS = '..'
# IP_ADDRESS = CONST.IP_ADDRESS
DST_PORT = CONST.DST_PORT
INTERFACE = CONST.INTERFACE
SUBSCRIBE_TOPIC = CONST.SUBSCRIBE_TOPIC
PUBLISH_TOPIC_SUFFIX = CONST.PUBLISH_TOPIC_SUFFIX
CLIENTID_SUFFIX = CONST.CLIENTID_SUFFIX
BIG_MQTT_VERSION = CONST.BIG_MQTT_VERSION

SLOW_DOS_CONNECTIONS_SUM = CONST.SLOW_DOS_CONNECTIONS_SUM
POISON_MESSAGE = CONST.POISON_MESSAGE

ERROR_MESSAGE = {
    0: 'CHECK UR SUB MODE FORMAT LIKE "s,p,d,u" ',
    1: 'CHECK UR SUB MODE INPUT LIKE "s,p,d,u" ',
    2: 'PLEASE CHECK UR MODE HELP -h or --help'
}


def usege():
    intro = """
    0.BASE PART::
    -h --help                   Show this help message and exit
    -ip --ipaddress             Specify the broker address (defaults to <127.0.0.1>)
    -p --port                   Specify the broker port (defaults to <1883>)
    -i --interface              Specify the broker interface (defaults to <sns>)
    -mv --mqttversion           Specify the broker mqtt version (defaults to <5>)
    -st --subtopic              Specify the broker mqtt subscribe topic (defaults to <test/#>)
    -pts --pubtopicsuffix       Specify the broker mqtt publish topic suffix (defaults to <test/>)
    -cids --clientidsuffix      Specify the broker mqtt publish topic suffix (defaults to <mqtt_>)
    1.ADVANCED PART::
    >1.1 SCAPY PART::
    >>s                         Specify using scapy
    -f --flood                  Specify using flood attack
    -m --mitm                   Specify using mitm attack
    -e --editmsg                Specify using mitm attack and specify msg (defaults to <''>)
    -fz --fuzz                  Specify using fuzzing attack
    >1.2 PAHO2 PART::
    >>p                         Specify using paho2
    -f --flood                  Specify using flood attack
    -ez --ezflag                Specify using easy flood attack or not (defaults to <True/Yes>)
    -m --mitm                   Specify using mitm attack
    -e --editmsg                Specify using mitm attack and specify msg (defaults to <''>)
    -sd --slowdos               Specify using slow dos attack
    -c --count                  Specify using slow dos attack and specify connections count(defaults to <3000>)
    -b --bruteforce             Specify using brute force attack
    >1.3 DETECT PART::
    >>d                         Specify using detect mode
    -b --bruteforce             Specify detect brute force attack
    -fz --fuzz                  Specify detect fuzzing attack
    -f --flood                  Specify detect flood attack
    >1.4 UTILS PART::
    >>u                         Specify using some utils
    -gi --getiface              CHECKING ALL INTERFACE ON THIS DEVICE
    """
    return intro


def main():
    global IP_ADDRESS, DST_PORT, INTERFACE, SUBSCRIBE_TOPIC, PUBLISH_TOPIC_SUFFIX, CLIENTID_SUFFIX, BIG_MQTT_VERSION, SLOW_DOS_CONNECTIONS_SUM, POISON_MESSAGE
    parser = argparse.ArgumentParser(description="this is a tool for mqtt attack or detect")
    const_group = parser.add_argument_group('Prefix constant')
    const_group.add_argument(
        "-ip", "--ipaddress", action='store', default='127.0.0.1', const='127.0.0.1', nargs='?', required=False,
        type=str,
        help='Specify the broker address (defaults to <127.0.0.1>)'
    )
    const_group.add_argument(
        "-p", "--port", action='store', default=1883, const=1883, nargs='?', required=False, type=int,
        help='Specify the broker port (defaults to <1883>)'
    )
    const_group.add_argument(
        "-i", "--interface", action='store', default='sns', const='sns', nargs='?', required=False, type=str,
        help='Specify the broker interface (defaults to <sns>)'
    )
    const_group.add_argument(
        "-mv", "--mqttversion", action='store', default=5, const=5, nargs='?', required=False, type=int,
        help='Specify the broker mqtt version (defaults to <5>)'
    )
    const_group.add_argument(
        "-st", "--subtopic", action='store', default='test/#', const='test/#', nargs='?', required=False, type=str,
        help='Specify the broker mqtt subscribe topic (defaults to <test/#>)'
    )
    const_group.add_argument(
        "-pts", "--pubtopicsuffix", action='store', default='test/', const='test/', nargs='?', required=False, type=str,
        help='Specify the broker mqtt publish topic suffix (defaults to <test/>)'
    )
    const_group.add_argument(
        "-cids", "--clientidsuffix", action='store', default='mqtt_', const='mqtt_', nargs='?', required=False,
        type=str,
        help='Specify the broker mqtt publish topic suffix (defaults to <mqtt_>)'
    )
    # mode_group = parser.add_mutually_exclusive_group()
    # mode_group.add_argument(
    #     '-s', '--scapy', action='store_true', help='Specify using scapy'
    # )
    # mode_group.add_argument(
    #     '-p', '--paho2', action='store_true', help='Specify using paho2'
    # )
    # mode_group.add_argument(
    #     '-d', '--detect', action='store_true', help='Specify using detect mode'
    # )
    # 子解释器
    sub_mode = parser.add_subparsers(
        help='CHOOSE THE MODE',
        title='SUB MODE',
        description='Specify using scapy/paho2/detect/getiface. usage:main.py -p 1883 s -f',
        dest='sub_mode'
    )
    # scapy功能模块
    sub_mode_scapy = sub_mode.add_parser('s', help='Specify using scapy')
    scapy_attack_mode = sub_mode_scapy.add_mutually_exclusive_group()
    scapy_attack_mode.add_argument(
        '-f', '--flood', action='store_true', help='Specify using flood attack'
    )
    scapy_attack_mode.add_argument(
        '-m', '--mitm', action='store_true', help='Specify using mitm attack'
    )
    scapy_attack_mode.add_argument(
        '-fz', '--fuzz', action='store_true', help='Specify detect fuzzing attack'
    )
    sub_mode_scapy.add_argument(
        '-e', '--editmsg', action='store', default='', const='', nargs='?', required=False, type=str,
        help='Specify using mitm attack and specify msg (defaults to <\'\'>)'
    )
    # paho2功能模块
    sub_mode_paho2 = sub_mode.add_parser('p', help='Specify using paho2')
    paho2_attack_mode = sub_mode_paho2.add_mutually_exclusive_group()
    paho2_attack_mode.add_argument(
        '-f', '--flood', action='store_true', help='Specify using flood attack'
    )
    paho2_attack_mode.add_argument(
        '-m', '--mitm', action='store_true', help='Specify using mitm attack'
    )
    paho2_attack_mode.add_argument(
        '-sd', '--slowdos', action='store_true', help='Specify using slow dos attack'
    )
    paho2_attack_mode.add_argument(
        '-b', '--bruteforce', action='store_true', help='Specify using brute force attack'
    )
    sub_mode_paho2.add_argument(
        '-e', '--editmsg', action='store', default='', const='', nargs='?', required=False, type=str,
        help='Specify using mitm attack and specify msg (defaults to <\'\'>)'
    )
    sub_mode_paho2.add_argument(
        '-ez', '--ezflag', action='store_false', required=False,
        help='Specify using mitm attack and specify msg (defaults to <True/Yes>)'
    )
    sub_mode_paho2.add_argument(
        '-c', '--count', action='store', default=3000, const=3000, nargs='?', required=False, type=int,
        help='Specify using mitm attack and specify msg (defaults to <3000>)'
    )
    # detect模块
    sub_mode_detect = sub_mode.add_parser('d', help='Specify using detect mode')
    detect_mode = sub_mode_detect.add_mutually_exclusive_group()
    detect_mode.add_argument(
        '-b', '--bruteforce', action='store_true', help='Specify using brute force attack'
    )
    detect_mode.add_argument(
        '-fz', '--fuzz', action='store_true', help='Specify detect fuzzing attack'
    )
    detect_mode.add_argument(
        '-f', '--flood', action='store_true', help='Specify using flood attack'
    )
    # utils模块
    sub_mode_utils = sub_mode.add_parser('u', help='Specify using some utils')
    utils_mode = sub_mode_utils.add_mutually_exclusive_group()
    utils_mode.add_argument(
        '-gi', '--getiface', action='store_true', help='CHECKING ALL INTERFACE ON THIS DEVICE'
    )

    args = parser.parse_args()
    # 分发常量
    if args.ipaddress is not None:
        IP_ADDRESS = CONST.IP_ADDRESS = args.ipaddress
    if args.port is not None:
        DST_PORT = CONST.DST_PORT = args.port
    if args.interface is not None:
        INTERFACE = CONST.INTERFACE = args.interface
    if args.mqttversion is not None:
        BIG_MQTT_VERSION = CONST.BIG_MQTT_VERSION = args.mqttversion
    if args.subtopic is not None:
        SUBSCRIBE_TOPIC = CONST.SUBSCRIBE_TOPIC = args.subtopic
    if args.pubtopicsuffix is not None:
        PUBLISH_TOPIC_SUFFIX = CONST.PUBLISH_TOPIC_SUFFIX = args.pubtopicsuffix
    if args.clientidsuffix is not None:
        CLIENTID_SUFFIX = CONST.CLIENTID_SUFFIX = args.clientidsuffix
    # 分发指定参数
    if args.sub_mode is None:
        print(ERROR_MESSAGE.get(0))
    elif args.sub_mode == 's':
        POISON_MESSAGE = CONST.POISON_MESSAGE = args.editmsg
        if args.flood:
            import learn.scapy_learn as sl
            sl.CONNECT_ATTACK_EMU_1(mode=0)
        elif args.mitm:
            import mitm.mitm_5_learn as m5
            m5.open_sniffing()
        elif args.fuzz:
            import learn.scapy_learn as sl
            sl.CONNECT_ATTACK_EMU_1(mode=1)
        else:
            print(ERROR_MESSAGE.get(2))
    elif args.sub_mode == 'p':
        POISON_MESSAGE = CONST.POISON_MESSAGE = args.editmsg
        SLOW_DOS_CONNECTIONS_SUM = CONST.SLOW_DOS_CONNECTIONS_SUM = args.count
        ez_flag = args.ezflag
        if args.flood:
            import paho2.MadPublisher as madlion
            madlion.show_mad_lion(
                broker=IP_ADDRESS,
                port=int(DST_PORT),
                api_version=mqtt.CallbackAPIVersion.VERSION2 if BIG_MQTT_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1,
                ezflag=ez_flag
            )
        elif args.mitm:
            import paho2.ViroseSubscriber as vs
            # print(type(BIG_MQTT_VERSION))
            # print(BIG_MQTT_VERSION)
            # print(type(IP_ADDRESS))
            # print(IP_ADDRESS)
            # print(type(DST_PORT))
            # print(DST_PORT)
            vs.poison(
                api_version=mqtt.CallbackAPIVersion.VERSION2 if BIG_MQTT_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1,
                target_broker=IP_ADDRESS,
                target_port=int(DST_PORT)
            )
        elif args.slowdos:
            import paho2.slow_dos as sd
            credentials = sd.Credentials()
            cert_key_paths = [None, None, None]
            timew = int(SLOW_DOS_CONNECTIONS_SUM * 0.04) if (SLOW_DOS_CONNECTIONS_SUM * 0.04 > 60) else 60
            ans2 = sd.slow_dos(IP_ADDRESS,
                               mqtt.CallbackAPIVersion.VERSION2 if BIG_MQTT_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1,
                               DST_PORT, credentials, cert_key_paths, SLOW_DOS_CONNECTIONS_SUM, timew)
            print(F'SLOW DOS RESULT == <{ans2}>')
        elif args.bruteforce:
            import paho2.brute_force as bf
            import learn.randomIP as rip
            bf_res = bf.brute_force(
                ip_target=IP_ADDRESS,
                version=mqtt.CallbackAPIVersion.VERSION2 if BIG_MQTT_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1,
                port=DST_PORT,
                username=rip.RANDOM_NAME(suffix='', randomLen=6),
                wordlist_path='/paho2/words.txt'
            )
            print(f'BRUTE FORCE RESULT == <{bf_res}>')
            ub_res = bf.username_bug(
                ip_target=IP_ADDRESS,
                version=mqtt.CallbackAPIVersion.VERSION2 if BIG_MQTT_VERSION == 5 else mqtt.CallbackAPIVersion.VERSION1,
                port=DST_PORT
            )
            print(f'USERNAME_BUG_RESULT == <{ub_res}>')
        else:
            print(ERROR_MESSAGE.get(2))
    elif args.sub_mode == 'd':
        if args.bruteforce:
            import guardian.detect_bruteforce as dbf
            dbf.opening_sniff()
        elif args.fuzz:
            import guardian.anti_fuzzing as af
            af.opening_sniff()
        elif args.flood:
            import guardian.detect_flood as df
            df.opening_sniff()
        else:
            print(ERROR_MESSAGE.get(2))
    elif args.sub_mode == 'u':
        if args.getiface:
            import utils.get_interface as gi
            gi.get_all_interfaces()
        else:
            print(ERROR_MESSAGE.get(2))

    else:
        print(ERROR_MESSAGE.get(1))
    print(args)


if __name__ == '__main__':
    main()
    # parser = argparse.ArgumentParser(description="this is a tool for mqtt attack or detect")
    # parser.add_argument('-f', '--fuck', action='help')
    # g = parser.add_mutually_exclusive_group()
    # g.add_argument('-a', '--option1', help='Option 1')
    # g.add_argument('-b', '--option2', help='Option 2')
    # g.add_argument('-c', '--option3', help='Option 3')
    # subparsers = parser.add_subparsers(dest='subb', help='sub-command help')
    # parser_z = subparsers.add_parser('z', help='z help')
    # parser_y = subparsers.add_parser('y', help='y help')
    # sb2 = parser_z.add_subparsers(help='sub-command help222')
    # parser_zz = sb2.add_parser('zz', help='zz help')
    # parser_zz2 = sb2.add_parser('zz2', help='zz2 help')
    # parser_zz3 = sb2.add_parser('zz3', help='zz3 help')
    # sb3 = parser_y.add_subparsers(help='sub-command help333')
    # parser_yy = sb3.add_parser('yy', help='yy help')
    # parser_yy2 = sb3.add_parser('yy2', help='yy2 help')
    # parser_yy3 = sb3.add_parser('zz3', help='zz3 help')
    # args = parser.parse_args()
    # print(args)
