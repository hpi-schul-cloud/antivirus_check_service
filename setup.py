#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages


setup(
    name='antivirus_service',
    version='0.1.0',
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
