# -*- coding: utf-8 -*-
import pyclamd
import logging
from datetime import datetime

from antivirus_service.pyclamd_overrride import scan_stream_overload

# overload scan_stream to use the response content iterator
pyclamd.ClamdNetworkSocket.scan_stream = scan_stream_overload


class Clamd(object):
    def __init__(self, settings):
        self.clamd_config = settings
        logging.info(self.clamd_config)

    def get_connection(self):
        if self.clamd_config['type'] == 'network':
            return pyclamd.ClamdNetworkSocket(
                host=self.clamd_config['host'],
                port=self.clamd_config['port']
            )
        return pyclamd.ClamdUnixSocket()

    def scan_file(self, response):
        logging.info('Start scan')
        try:
            cd = self.get_connection()
        except pyclamd.ConnectionError:
            logging.exception('clamd: Can\'t connect to Clamd\'s network socket.')
            return
        try:
            result = cd.scan_stream(response)
        except pyclamd.BufferTooLongError:
            logging.exception('	clamd: BufferTooLongError.')
            return
        except pyclamd.ConnectionError:
            logging.exception('clamd: Can\'t connect to Clamd\'s network socket.')
            return

        logging.info(result)
        # result is None if no virus was found,
        # otherwise: {'<path>': ('FOUND', '<signature>')}
        # or {'<path>': ('ERROR', '<error message>')}

        if result is None:
            return False, None
        elif result['stream'][0] == 'ERROR':
            raise Exception('An error occured with the viruschecker: {}'.format(result['stream'][1]))
        else:
            return True, result['stream'][1]

    def get_version(self):
        cd = self.get_connection()
        version = cd.version().split()
        # ['ClamAV', '0.99.2/24386/Mon', 'Mar', '12', '08:10:47', '2018']

        # do we want the timestamp?
        datetime_object = datetime.strptime('{0} {1} {2} {3}'.format(
            version[2], version[3], version[5], version[4]), '%b %d %Y %H:%M:%S')

        return {
            'clamd-version': version[1],
            'clamd-database-version': datetime_object.strftime("%Y/%m/%d - %H:%M:%S")
        }
