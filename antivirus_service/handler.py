# -*- coding: utf-8 -*-
import os
import pwd
import json
import time
import logging
import pyclamd
import requests
import tempfile

from pprint import pformat


class ScanHandler(object):
    def __init__(self, settings):
        self.clamav_uid = pwd.getpwnam('clamav').pw_uid
        self.clamav_gid = pwd.getpwnam('clamav').pw_gid
        self.settings = settings
        self.config = settings.config[settings.env]


class ScanFileHandler(ScanHandler):
    def download_file(self, download_uri, access_token):
        headers = {}
        if access_token:
            headers['Authorization'] = 'Bearer %s' % access_token

        # we try to download the file multiple times, just for the case,
        # that the scan request was triggered before the file upload 
        # has been finished
        last_exception_message = ''
        for i in range(5):
            try:
                r = requests.get(download_uri, stream=True, headers=headers)
                if r.status_code != 200:
                    raise Exception('Bad status code: {}'.format(r.status_code))
                else:
                    break
            except Exception as e:
                last_exception_message = str(e)
                logging.error('An exception occured "{0}"'.format(last_exception_message))
                time.sleep(2**i)
        else:
            raise Exception('File could not downloaded: {0} - after {1} seconds'.format(last_exception_message, 2**(i+1) - 1))

        tmpfile = tempfile.NamedTemporaryFile()
        os.chown(tmpfile.name, self.clamav_uid, self.clamav_gid)

        logging.info('Create file')
        logging.info(tmpfile.name)
        with open(tmpfile.name, 'wb') as f:
            for chunk in r.iter_content(1024):
                f.write(chunk)
        return tmpfile

    def scan_file(self, tmpfile):
        logging.info('Start scan')
        cd = pyclamd.ClamdAgnostic()
        result = cd.scan_file(tmpfile.name)
        tmpfile.close()

        logging.info(result)
        # result is None if no virus was found,
        # otherwise: {'<path>': ('FOUND', '<signature>')}
        if result is None:
            return False, None
        return True, result[tmpfile.name][1]

    def callback(self, callback_uri, access_token, scan_result, signature):
        logging.info('Start callback')
        headers = {}
        if access_token:
            headers['Authorization'] = 'Bearer %s' % access_token

        result = {
            'virus_detected': scan_result,
            'virus_signature': signature
        }
        logging.info(result)
        response = requests.put(callback_uri, headers=headers, data=json.dumps(result))
        logging.info(response.status_code)
        logging.info('------------- END PROCESS SCAN -------------')

    def parse_body(self, body):
        payload = json.loads(bytes(body).decode('utf-8'))
        assert 'download_uri' in payload
        assert 'callback_uri' in payload
        return payload

    def handle_message(self, payload):
        '''
        handles antivirus scan file requests
        '''
        logging.info('------------- INCOMING MESSAGE -------------')
        logging.info(payload)

        download_uri = payload['download_uri']
        callback_uri = payload['callback_uri']
        access_token = payload.get('access_token', None)

        tmpfile = self.download_file(download_uri, access_token)
        scan_result, signature = self.scan_file(tmpfile)
        self.callback(callback_uri, access_token, scan_result, signature) 


class ScanUrlHandler(ScanHandler):
    def parse_body(self, body):
        payload = json.loads(bytes(body).decode('utf-8'))
        assert 'url' in payload
        assert 'callback_uri' in payload
        return payload

    def callback(self, callback_uri, access_token, blacklisted, full_report):
        logging.info('Start callback')
        headers = {}
        if access_token:
            headers['Authorization'] = 'Bearer %s' % access_token

        result = {
            'blacklisted': blacklisted,
            'full_report': full_report
        }
        logging.info(result)

        response = requests.put(callback_uri, headers=headers, data=json.dumps(result))
        logging.info(response.status_code)
        logging.info('------------- END PROCESS SCAN -------------')

    def scan_url(self, url):
        logging.info('Start scan')

        api_key = self.config['virustotal']['api_key']
        
        params = {'apikey': api_key, 'url': url}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        scan_response = response.json()
        logging.info(scan_response)

        # we have to wait for the result
        headers = {
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent' : 'gzip,  Antivirus checker'
        }
        for i in range(10):
            params = {'apikey': api_key, 'resource': scan_response['scan_id']}
            response = requests.post('http://www.virustotal.com/vtapi/v2/url/report', data=params, headers=headers)
            result_response = response.json()
            logging.info(result_response)

            # scan job is processed
            if 'positives' in result_response:
                break
            time.sleep(2**i)
        else:
            d = 2**(i+1) - 1
            raise Exception('Scan report could not downloaded after {0} seconds'.format(d))

        return result_response['positives'] != 0, result_response

    def handle_message(self, payload):
        '''
        handles antivirus scan url requests
        '''
        logging.info('------------- INCOMING MESSAGE -------------')
        logging.info(payload)

        url = payload['url']
        callback_uri = payload['callback_uri']
        access_token = payload.get('access_token', None)

        blacklisted, full_report = self.scan_url(url)
        self.callback(callback_uri, access_token, blacklisted, full_report)
