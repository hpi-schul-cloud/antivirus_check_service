#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open("requirements.txt", "r") as fh:
    requirements = fh.readlines()

setup(
    name='antivirus_service',
    version='2.0.5',
    description='This service detects virus in downloaded files by using clamd',
    author='hpi schul-cloud',
    packages=find_packages(exclude='tests'),
    install_requires=[req for req in requirements if req[:2] != "# "],
    entry_points={
        'console_scripts': [
            'antivirus=antivirus_service.service:main'
        ]
    }
)
