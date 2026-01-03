import errno
import logging
import os
import struct

from blackfyre.common import MessageType, LOG_DIR

logger = logging.getLogger("BlackfyreUtil")
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)


def get_message_type(data):

    data = struct.unpack("B", data)[0]

    message_type = MessageType(data)

    return message_type


def get_message_size(data):

    message_size = struct.unpack(">I", data)[0]

    return message_size


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def setup_custom_logger(name):

    mkdir_p(LOG_DIR)

    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.FileHandler('{}.log'.format(os.path.join(LOG_DIR,name)), mode='w')
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    my_logger = logging.getLogger(name)
    logging.basicConfig(level=logging.INFO)
    my_logger.setLevel(logging.INFO)
    my_logger.addHandler(handler)
    return my_logger