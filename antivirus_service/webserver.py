# -*- coding: utf-8 -*-
import json
import time
import base64
import logging
import aio_pika
import asyncio
from aiohttp import web
from pprint import pformat
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

    def run(self):
        app = web.Application()
        app.router.add_get('/', self.index)
        app.router.add_post('/scan/file', self.handle_file)
        app.router.add_post('/scan/url', self.handle_uri)
        app.router.add_get('/antivirus-version', self.handle_version)

        app.on_startup.append(self.on_startup)
        app.on_shutdown.append(self.on_shutdown)

        self.app = app
        web.run_app(app)

    def stop(self):
        self.app.loop.close()

    async def on_startup(self, app):
        print("Establish amqp connection and channel")
        self.loop = asyncio.get_event_loop()
        self.connection = await aio_pika.connect_robust(self.amqp_config['url'], loop=self.loop)
        self.channel = await self.connection.channel()
        try:
          self.loop.run_forever()
        finally:
          self.loop.run_until_complete(self.connection.close())
        self.clamd = Clamd(self.clamd_config)

    async def on_shutdown(self, app):
        print("Close amqp connection and channel")
        self.loop.run_until_complete(self.channel.close())
        self.loop.run_until_complete(self.connection.close())

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
            "scan url request": {
                "description": "Scan Url (using virustotal), report back to given webhook Uri",
                "path": "/scan/url",
                "method": "POST",
                "params": {
                    "url": {
                        "type": "string",
                        "description": "Url to scan using virustotal"
                    },
                    "callback_uri": {
                        "type": "string",
                        "description": "Complete Uri to the callback uri"
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

            await self.enqueue_scan_file_request(body)
            return web.Response(status=202)

        except AssertionError:
            return web.Response(status=422, text='Unprocessable Entity: missing parameter')
        except Exception as e:
            return web.Response(status=500, text=str(e))

    @auth_required
    async def handle_uri(self, request):
        body = await request.read()
        try:
            payload = json.loads(bytes(body).decode('utf-8'))
            assert 'url' in payload
            assert 'callback_uri' in payload

            await self.enqueue_scan_url_request(body)
            return web.Response(status=202, text='The request has been accepted for processing, but the processing has not been completed.')

        except AssertionError:
            return web.Response(status=422, text='Unprocessable Entity: missing parameter')
        except Exception as e:
            return web.Response(status=500, text=str(e))

    async def enqueue_scan_file_request(self, body):
        await self.channel.default_exchange.publish(
            aio_pika.Message(body=body), routing_key=self.amqp_config['scan_file']['routing_key']
        )

    async def enqueue_scan_url_request(self, body):
        await self.channel.default_exchange.publish(
            aio_pika.Message(body=body), routing_key=self.amqp_config['scan_url']['routing_key']
        )

    @auth_required
    async def handle_version(self, request):
        return web.json_response(self.clamd.get_version())
