# -*- coding: utf-8 -*-
import json
import base64
import logging

import pika
from aiohttp import web
from functools import wraps

from antivirus_service.clamd import Clamd


def auth_required(f):
    @wraps(f)
    def wrapper(self, request):
        auth_header = request.headers.get('Authorization', None)
        if auth_header:
            key = auth_header.split('Basic ')[-1]
            if key in self.auth_keys:
                return f(self, request)

        raise web.HTTPForbidden(
            headers={'WWW-Authenticate': 'Basic realm="Antivirus Check Service"'})
    return wrapper


class Webserver(object):
    def __init__(self, settings):
        self.amqp_config = settings.config[settings.env]['amqp']
        self.clamd_config = settings.config[settings.env]['clamd']
        self.auth_keys = [
            base64.b64encode(bytes(entry, 'utf-8')).decode('ascii')
            for entry in settings.config[settings.env]['webserver']['auth_users']]

        self.clamd = Clamd(self.clamd_config)

        app = web.Application()
        app.router.add_get('/', self.index)
        app.router.add_post('/scan/file', self.handle_file)
        app.router.add_get('/antivirus-version', self.handle_version)
        self.app = app

    def run(self):
        web.run_app(self.app)

    def stop(self):
        self.app.loop.close()

    async def index(self, request):
        doc = {
            "scan file request": {
                "description": "Download file and scan against virus (using local clamd), report back to given webhook uri",
                "path": "/scan/file",
                "method": "POST",
                "params": {
                    "download_uri": {
                        "type": "string",
                        "description": "Complete uri to the downloadable file"
                    },
                    "callback_uri": {
                        "type": "string",
                        "description": "Complete uri to the callback uri"
                    },
                }
            },
            "clamav daemon version": {
                "description": "Get clamav daemon version and last database update",
                "path": "/antivirus-version",
                "method": "GET"
            },
        }
        return web.json_response(doc)

    @auth_required
    async def handle_file(self, request):
        body = await request.read()
        logging.info("Incoming request with body: {}".format(body))
        try:
            payload = json.loads(bytes(body).decode('utf-8'))
            assert 'download_uri' in payload
            assert 'callback_uri' in payload

            self.enqueue_scan_file_request(body)
            return web.Response(status=202)

        except AssertionError:
            return web.Response(status=422, text='Unprocessable Entity: missing parameter')
        except Exception as e:
            logging.error('error', exc_info=True)
            return web.Response(status=500, text=str(e))

    def enqueue_scan_file_request(self, body):
        self.send(body, self.amqp_config['scan_file']['routing_key'])

    def send(self, body, routing_key):
        params = pika.URLParameters(self.amqp_config['url'])
        with pika.BlockingConnection(params) as con:
            with con.channel() as channel:
                channel.basic_publish(body=body, exchange=self.amqp_config['exchange'], routing_key=routing_key)

    @auth_required
    async def handle_version(self, request):
        return web.json_response(self.clamd.get_version())
