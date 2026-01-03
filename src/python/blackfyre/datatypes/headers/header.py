import os
from blackfyre.util import setup_custom_logger

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


class Header(object):

    __slots__ = []

    def __int__(self):
        pass

    def display_header(self):

        # Obtain the actual class name
        header_type = self.__class__.__name__

        logger.info(f"******************* Header Type:{header_type} *******************")

        number_of_fields = len(self.__slots__)

        for index,  attribute in enumerate(self.__slots__):
            value = getattr(self, attribute)

            logger.info(f"({index+1}/{number_of_fields}) Field:{attribute[1:]:<30}  Value:{value}")

        logger.info(f"***************** END Header Type:{header_type} ****************")

    @classmethod
    def from_pb(cls, header_pb):

        raise NotImplementedError
