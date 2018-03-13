# -*- coding: utf-8 -*-
import sys
import struct
import logging
import socket
from pyclamd import BufferTooLongError


'''
Override pyclamd scan_stream method to use the Response content iterator (by requests)
We dont't want to complete read the file into a buffer, but instead read the file in
chunks and send the chunks directly to clamd
'''

def scan_stream_overload(self, stream, chunk_size=4096):
    """
    Scan a buffer

    on Python3.X :
        - input (function): request

    return either:
        - (dict): {filename1: "virusname"}
        - None: if no virus found

    May raise :
        - BufferTooLongError: if the buffer size exceeds clamd limits
        - ConnectionError: in case of communication problem
    """

    try:
        self._init_socket()
        self._send_command('INSTREAM')

    except socket.error:
        raise ConnectionError('Unable to scan stream')

    for chunk in stream.iter_content(chunk_size):
        if not chunk:
            break
        size = struct.pack('!L', len(chunk))
        try:
            self.clamd_socket.send(size)
            self.clamd_socket.send(chunk)
        except socket.error as e:
            raise Exception('A network socket error occured: "{0}" (maybe file too large)'.format(e))

    # Terminating stream
    self.clamd_socket.send(struct.pack('!L', 0))

    result='...'
    dr = {}
    while result:
        try:
            result = self._recv_response()
        except socket.error:
            raise ConnectionError('Unable to scan stream')

        if len(result) > 0:

            if result == 'INSTREAM size limit exceeded. ERROR':
                raise BufferTooLongError(result)

            filename, reason, status = self._parse_response(result)

            if status == 'ERROR':
                dr[filename] = ('ERROR', '{0}'.format(reason))

            elif status == 'FOUND':
                dr[filename] = ('FOUND', '{0}'.format(reason))

    self._close_socket()
    if not dr:
        return None
    return dr