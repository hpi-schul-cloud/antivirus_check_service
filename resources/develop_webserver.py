# -*- coding: utf-8 -*-
#!/usr/bin/python3
from aiohttp import web


class Webserver(object):
    def run(self, port=7000):
        app = web.Application()
        app.router.add_get('/', self.index)
        app.router.add_get('/uninfectedfile', self.handle_uninfected_file)
        app.router.add_get('/infectedfile', self.handle_infected_file)
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
                'path': '/infectedFile'
            },
            'get uninfected file request': {
                'description': 'returns an uninfected file',
                'method': 'GET',
                'path': '/uninfectedFile'
            }
        }
        return web.json_response(doc)

    async def handle_infected_file(self, request):
        headers = {'content-type': 'application/octed-stream'}
        return web.Response(headers=headers, text=open('./virus.txt').read())

    async def handle_uninfected_file(self, request):
        headers = {'content-type': 'application/octed-stream'}
        return web.Response(headers=headers, text=open('./no_virus.txt').read())

    async def handle_report(self, request):
        msg =  '--- Scan Request Result ---\n'
        msg += await request.text()
        print(msg)
        return web.Response(text=msg)


webserver = Webserver()
webserver.run()