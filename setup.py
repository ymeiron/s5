#!/usr/bin/env python
from distutils.core import setup
import re

with open('s5/_version.py', 'r') as f:
    __version__ = re.match(r"""__version__ = ["'](.*?)['"]""", f.read()).group(1)

setup(name='s5',
    version=__version__,
    description='SciNet Super Simple Secrets Server',
    author='Yohai Meiron',
    author_email='yohai.meiron@scinet.utoronto.ca',
    packages=['s5'],
    entry_points={
        'console_scripts': [
            's5server=s5:server',
            's5client=s5:client'
        ]
    },
    install_requires=['falcon']
)
