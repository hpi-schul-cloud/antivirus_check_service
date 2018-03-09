# -*- coding: utf-8 -*-
import os
import sys
import yaml
import click
import logging

from antivirus_service.webserver import Webserver
from antivirus_service.handler import ScanFileHandler, ScanUrlHandler
from antivirus_service.consumer import ScanFileConsumer, ScanUrlConsumer


class AntivirusSettings(object):
    def __init__(self, env, debug):
        self.env = env
        self.project_root = os.path.dirname(os.path.abspath(__file__))
        self.config = yaml.load(
            open(os.path.join(self.project_root, 'config.yml')).read())

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