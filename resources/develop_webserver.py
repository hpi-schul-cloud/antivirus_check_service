# -*- coding: utf-8 -*-
#!/usr/bin/python3
import os
from aiohttp import web
from concurrent.futures._base import CancelledError


class Webserver(object):
    def run(self, port=7000):
        app = web.Application()
        app.router.add_get('/', self.index)
        app.router.add_get('/scanfile', self.handle_scanfile)
        app.router.add_put('/report', self.handle_report)

        app.on_startup.append(self.on_startup)
        app.on_shutdown.append(self.on_shutdown)

        self.app = app
        web.run_app(app, port=port)

    def stop(self):
        self.app.loop.close()

    async def on_startup(self, app):
        pass

    async def on_shutdown(self, app):
        pass

    async def index(self, request):
        doc = {
            'get infected file request': {
                'description': 'returns an infected file',
                'method': 'GET',
                'path': '/scanfile',
                'params': {
                    'desc': 'files name - in resources folder',
                    'name': 'name'
                }
            },
        }
        return web.json_response(doc)

    def handle_scanfile(self, request):
        path = './' + request.rel_url.query['name']
        statinfo = os.stat(path)

        response = web.StreamResponse()
        response.content_length = statinfo.st_size
        response.content_type = 'application/octet-stream'
        yield from response.prepare(request)

        try:
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(2048)
                    if not chunk:
                        return response
                    response.write(chunk)
        finally:
            yield from response.write_eof() 

    async def handle_report(self, request):
        msg =  '--- Scan Request Result ---\n'
        msg += await request.text()
        print(msg)
        return web.Response(text=msg)


webserver = Webserver()
webserver.run()