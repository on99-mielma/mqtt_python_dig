from scapy.all import *
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)


def get_all_interfaces():
    interfaces = conf.ifaces
    logging.info(
        msg=f'\n{interfaces}\n'
    )


if __name__ == '__main__':
    get_all_interfaces()
