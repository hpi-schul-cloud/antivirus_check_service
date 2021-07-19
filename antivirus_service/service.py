# -*- coding: utf-8 -*-
import os
import sys
import yaml
import click
import logging
import environs

from antivirus_service.webserver import Webserver
from antivirus_service.handler import ScanFileHandler, ScanUrlHandler
from antivirus_service.consumer import ScanFileConsumer, ScanUrlConsumer


class AntivirusSettings(object):
    def __init__(self, env, debug):
        self.env = env
        self.project_root = os.path.dirname(os.path.abspath(__file__))
        self.config = {}
        
        env = Env()
        with env.prefixed(self.env.upper()+"_"):
            self.config[self.env]={}
            param="clamd"
            with env.prefixed(param.upper()+"_"):
                self.config[self.env][param]={}
                self.config[self.env][param]['type']=env("TYPE","network")
                self.config[self.env][param]['host']=env("HOST","clamav")
                self.config[self.env][param]['port']=env.int("PORT",3310)
                self.config[self.env][param]['directory']=env("DIRECTORY","/shared")
            param="webserver"
            with env.prefixed(param.upper()+"_"):
                self.config[self.env][param]={}
                self.config[self.env][param]['auth_users']=env.list("AUTH_USERS")
            param="virustotal"
            with env.prefixed(param.upper()+"_"):
                self.config[self.env][param]={}
                self.config[self.env][param]['api_key']=env.list("API_KEY")
            param="amqp"
            with env.prefixed(param.upper()+"_"):
                self.config[self.env][param]={}
                self.config[self.env][param]['url']=env("URL","amqp://rabbitmq/antivirus")
                with env.prefixed("SCAN_FILE_"):
                    self.config[self.env][param]['scan_file']={}
                    self.config[self.env][param]['scan_file']['queue']=env("QUEUE","scan_file")
                    self.config[self.env][param]['scan_file']['routing_key']=env("ROUTING_KEY","scan_file")
                with env.prefixed("SCAN_URL_"):
                    self.config[self.env][param]['scan_url']={}
                    self.config[self.env][param]['scan_url']['queue']=env("QUEUE","scan_url")
                    self.config[self.env][param]['scan_url']['routing_key']=env("ROUTING_KEY","scan_url")

        loglevel = logging.INFO if debug  else logging.ERROR
        logging.basicConfig(level=loglevel)


@click.group()
@click.option('--env', default='develop', help='environment')
@click.option('--debug/--no-debug', default=True)
@click.pass_context
def cli(ctx, env, debug):
    """Antivirus Service"""
    ctx.obj = AntivirusSettings(env, debug)


@cli.command()
@click.pass_context
def scan_file(ctx):
    """Run Antivirus Service - listen on message queue"""
    try:
        handler = ScanFileHandler(ctx.obj)
        consumer = ScanFileConsumer(ctx.obj, handler)
        consumer.run()
    except KeyboardInterrupt:
        consumer.stop()


@cli.command()
@click.pass_context
def scan_url(ctx):
    """Run Antivirus Service - listen on message queue"""
    try:
        handler = ScanUrlHandler(ctx.obj)
        consumer = ScanUrlConsumer(ctx.obj, handler)
        consumer.run()
    except KeyboardInterrupt:
        consumer.stop()


@cli.command()
@click.pass_context
def webserver(ctx):
    """Run Antivirus Service - webserver"""
    try:
        webserver = Webserver(ctx.obj)
        webserver.run()
    except KeyboardInterrupt:
        webserver.stop()

def main():
    cli(obj={})