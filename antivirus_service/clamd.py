# -*- coding: utf-8 -*-
import os
import pyclamd
import logging
import tempfile
from datetime import datetime


class Clamd(object):
    def __init__(self, settings):
        self.clamd_config = settings.config[settings.env].get('clamd', {
            'type': 'unix'
        })
        logging.info(self.clamd_config)

    def get_connection(self):
        if self.clamd_config['type'] == 'network':
            return pyclamd.ClamdNetworkSocket(
                host=self.clamd_config['host'],
                port=self.clamd_config['port']
            )
        return pyclamd.ClamdUnixSocket()

    def scan_file(self, filepath):
        cd = self.get_connection()
        result = cd.scan_file(filepath)

        logging.info(result)
        # result is None if no virus was found,
        # otherwise: {'<path>': ('FOUND', '<signature>')}

        if result is None:
            return False, None
        return True, result[filepath][1]

    def scan_stream(self, stream):
        cd = self.get_connection()

        logging.info('Start stream scan')
        result = cd.scan_stream(stream)

        logging.info(result)
        # result is None if no virus was found,
        # otherwise: {'stream': ('FOUND', '<signature>')}

        if result is None:
            return False, None
        return True, result['stream'][1]

    def scan(self, response):
        if self.clamd_config['type'] == 'network':
            return self.scan_stream(response.raw.read())
        else:
            tmpfile = tempfile.NamedTemporaryFile()

            # had issues with reading the tempfile
            # after clamd was updated by freshclam
            # had to manually restart clamd!
            # => set readable to all users
            os.chmod(tmpfile.name, 0o644)

            logging.info('Create file')
            logging.info(tmpfile.name)
            with open(tmpfile.name, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)

            logging.info('Start file scan')
            result = self.scan_file(tmpfile.name)
            tmpfile.close()

            return result

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
