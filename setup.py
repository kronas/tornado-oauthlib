#!/usr/bin/env python
# coding=utf-8


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from email.utils import parseaddr

import tornado_oauthlib

author, author_email = parseaddr(tornado_oauthlib.__author__)

setup(
    name='Tornado-OAuthlib',
    version=tornado_oauthlib.__version__,
    author=author,
    author_email=author_email,
    url=tornado_oauthlib.__homepage__,
    packages=[
        "tornado_oauthlib",
        "tornado_oauthlib.provider"
    ],
    description="OAuthlib for Tornado",
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=open('README.md').read(),
    license='BSD',
    install_requires=[
        'Tornado',
        'oauthlib>=0.6.2',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
