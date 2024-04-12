"""
检查文件是否存在
创建文件 / 读取文件到 defaultdict

将defaultdict写入到json


"""
import json
import os
import logging
import learn.randomIP as rip
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

# 指定目录和文件名
directory = 'guardian/'  # 目录路径
filename = 'blocklist.json'  # 文件名
file_path = os.path.join(directory, filename)
BLOCK_IP_PORT_SET = set()
BLOCK_IP_SET = set()
BLOCK_JSON = defaultdict(list)
BLOCK_JSON['IP'] = []
BLOCK_JSON['TCPIP'] = []
ERROR_MESSAGE = {
    0: "ADDRESS IS NONE"
}


def check_file_exist(path: str):
    global BLOCK_JSON
    if os.path.exists(path):
        logging.info(
            msg=f'file exist! going to next!'
        )
        with open(path) as f:
            data = json.load(f)
        f.close()
        BLOCK_JSON = defaultdict(list, data)
        BLOCK_IP_SET.update(BLOCK_JSON.get('IP'))
        BLOCK_IP_PORT_SET.update(BLOCK_JSON.get('TCPIP'))
    else:
        logging.info(
            msg=f'file not exist! creating now!'
        )
        # open(path, 'w').close()
        with open(path, 'w') as file:
            json.dump(BLOCK_JSON, file)
        file.close()
        logging.info(
            msg=f'file exist! created!'
        )


def check_address_format_and_add(address: str):
    if address is None:
        raise Exception(ERROR_MESSAGE.get(0))
    so = rip.Solution()
    ans = so.validIPAddress(address)
    if ans == "IPv4" or ans == "IPv6":
        BLOCK_IP_SET.add(address)
    else:
        BLOCK_IP_PORT_SET.add(address)


def save_set_to_json(path: str):
    global BLOCK_JSON
    IP_LIST = [bis for bis in BLOCK_IP_SET]
    TCPIP_LIST = [bips for bips in BLOCK_IP_PORT_SET]
    BLOCK_JSON['IP'] = IP_LIST
    BLOCK_JSON['TCPIP'] = TCPIP_LIST
    with open(path, 'w') as file:
        json.dump(BLOCK_JSON, file)
    file.close()


def init_and_return_dict_set(path: str):
    check_file_exist(path=path)
    global BLOCK_JSON
    return BLOCK_JSON, BLOCK_IP_SET, BLOCK_IP_PORT_SET


def init_add_save(address: str):
    global file_path
    check_file_exist(file_path)
    check_address_format_and_add(address)
    save_set_to_json(path=file_path)


def static_save():
    global file_path
    save_set_to_json(file_path)


def static_get():
    global file_path
    return init_and_return_dict_set(file_path)


if __name__ == '__main__':
    check_file_exist(path=file_path)
