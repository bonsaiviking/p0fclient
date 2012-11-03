#!/usr/bin/env python

from distutils.core import setup

setup( name='p0fclient',
        version='1.0',
        description='Client for p0f API',
        author='Daniel Miller',
        author_email='daniel@bonsaiviking.com',
        url='https://github.com/bonsaiviking/p0fclient',
        packages=['p0fclient'],
        requires=['ipaddr'],
        )
