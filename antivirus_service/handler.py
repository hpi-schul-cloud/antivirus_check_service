# -*- coding: utf-8 -*-
import json
import time
import logging
import requests

from antivirus_service.clamd import Clamd
from antivirus_service.url_validation import validate_url


class ScanHandler(object):
    def __init__(self, settings):
        self.config = settings.config[settings.env]
        self.clamd = Clamd(self.config['clamd'])
        self.download_retry_count = self.config['download_retry_count']
        self.download_allowed_origins = self.config['download_allowed_origins']
        self.callback_allowed_origins = self.config['callback_allowed_origins']

    def handle_error_message(self, payload, error_message):
        """
        handles error messages
        """
        logging.error('--- Start error message callback ---')
        logging.error('Scan request failed: %s', type(error_message).__name__)
        access_token = payload.get('access_token', None)
        callback_uri = payload.get('callback_uri', None)

        if not callback_uri:
            logging.error('On sending error message: empty callback_uri')
            return

        try:
            validate_url(callback_uri, self.callback_allowed_origins)
        except ValueError:
            logging.error('On sending error message: callback URL is not allowed')
            return

        headers = {'Content-type': 'application/json'}

        if access_token:
            headers['Authorization'] = 'Bearer %s' % access_token

        result = {'error': str(error_message)}
        try:
            requests.put(callback_uri, headers=headers, data=json.dumps(result), allow_redirects=False)
        except Exception as e:
            logging.error("On sending error message: callback could not be called: %s", type(e).__name__)


class ScanFileHandler(ScanHandler):
    def scan(self, download_uri, access_token):
        validate_url(download_uri, self.download_allowed_origins)
        headers = {}
        if access_token:
            headers['Authorization'] = 'Bearer %s' % access_token

        sleep_time = 2
        # we try to download the file multiple times, just for the case,
        # that the scan request was triggered before the file upload 
        # has been finished
        count = self.download_retry_count
        for i in range(1, count):
            try:
                # defining stream and timeout = just specifying the initial socket connect timeout, that's what we want
                r = requests.get(download_uri, stream=True, headers=headers, timeout=10, allow_redirects=False)
                if r.status_code != 200:
                    raise Exception('Bad status code: {0}'.format(r.status_code))
                else:
                    break
            except Exception as e:
                logging.info('file could not downloaded: for {0} time'.format(i))
                if i < count:
                    time.sleep(sleep_time)
        else:
            raise Exception('File could not downloaded after {0} seconds'.format(sleep_time * i))
        return self.clamd.scan_file(r)

    def callback(self, callback_uri, access_token, scan_result, signature):
        validate_url(callback_uri, self.callback_allowed_origins)
        logging.info('Start callback')
        headers = {'Content-type': 'application/json'}
        if access_token:
            headers['Authorization'] = 'Bearer %s' % access_token

        result = {
            'virus_detected': scan_result,
            'virus_signature': signature
        }
        logging.info(result)
        response = requests.put(callback_uri, headers=headers, data=json.dumps(result), allow_redirects=False)
        logging.info(response.status_code)
        logging.info('------------- END PROCESS SCAN -------------')

    def parse_body(self, body):
        payload = json.loads(bytes(body).decode('utf-8'))
        if not isinstance(payload, dict) or 'download_uri' not in payload or 'callback_uri' not in payload:
            raise ValueError('Missing required scan URL')
        validate_url(payload['download_uri'], self.download_allowed_origins)
        validate_url(payload['callback_uri'], self.callback_allowed_origins)
        return payload

    def handle_message(self, payload):
        """
        handles antivirus scan file requests
        """
        logging.info('------------- INCOMING MESSAGE -------------')
        logging.info('Processing scan request')

        download_uri = payload['download_uri']
        callback_uri = payload['callback_uri']
        access_token = payload.get('access_token', None)

        validate_url(download_uri, self.download_allowed_origins)
        validate_url(callback_uri, self.callback_allowed_origins)
        scan_result, signature = self.scan(download_uri, access_token)
        self.callback(callback_uri, access_token, scan_result, signature)

