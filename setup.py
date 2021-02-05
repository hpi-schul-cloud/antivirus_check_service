#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

path = './version'
version_file = open(path,'r')
get_version = version_file.read()
version_file.close()

setup(
    name='antivirus_service',
    version=get_version,
    description='This service detects virus in downloaded files by using clamd',
    author='matthias wiesner',
    packages=find_packages(exclude='tests'),
    install_requires=[
        'aio_pika'
    ],
    entry_points={
        'console_scripts': [
            'antivirus=antivirus_service.service:main'
        ]
    }
)
