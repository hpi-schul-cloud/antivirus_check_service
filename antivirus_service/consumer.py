# -*- coding: utf-8 -*-
import pika
import logging

from pprint import pformat


class ScanConsumer(object):
    def __init__(self, settings, handler):
        self.settings = settings
        self.handler = handler        
        self.amqp_config = settings.config[settings.env]['amqp']
        self.amqp_url = self.amqp_config['url']
        self.amqp_queue = None

        if 'heartbeat' in self.amqp_config:
            self.heartbeat = self.amqp_config['heartbeat']
        else:
            self.heartbeat = 120

        if 'blocked_connection_timeout' in self.amqp_config:
            self.blocked_connection_timeout = self.amqp_config['blocked_connection_timeout']
        else:
            self.blocked_connection_timeout = 60

        if 'socket_timeout' in self.amqp_config:
            self.socket_timeout = self.amqp_config['socket_timeout']
        else:
            self.socket_timeout = 5

    def _callback(self, ch, method, properties, body):
        try:
            payload = self.handler.parse_body(body)
        except Exception as e:
            # wrong body, log this error but give ack anyway
            ch.basic_ack(delivery_tag=method.delivery_tag)
            self.handler.handle_error_message(payload, e)
        else:
            # here we can decide, based on the exception type, if we re-enqueue the task
            # but currently we don't re-enqueue, but log this error (and/or email)
            ch.basic_ack(delivery_tag=method.delivery_tag)
            try:
                self.handler.handle_message(payload)
            except Exception as e:
                self.handler.handle_error_message(payload, e)

    def run(self):
        params = pika.URLParameters(self.amqp_url)
        params.heartbeat = self.heartbeat
        params.blocked_connection_timeout = self.blocked_connection_timeout
        params.socket_timeout = self.socket_timeout
        self.connection = pika.BlockingConnection(params)

        channel = self.connection.channel()
        channel.basic_consume(self._callback, queue=self.amqp_queue)
        channel.start_consuming()

    def stop(self):
        self.connection.close()


class ScanFileConsumer(ScanConsumer):
    def __init__(self, settings, handler):
        super().__init__(settings, handler)
        self.amqp_queue = self.amqp_config['scan_file']['queue']


class ScanUrlConsumer(ScanConsumer):
    def __init__(self, settings, handler):
        super().__init__(settings, handler)
        self.amqp_queue = self.amqp_config['scan_url']['queue']