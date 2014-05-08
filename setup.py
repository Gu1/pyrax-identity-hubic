#!/usr/bin/env python

from setuptools import setup

setup(
    name="pyrax-identity-hubic",
    version='0.1',
    description="HubiC identity module for rackspace's pyrax",
    author="Gu1",
    author_email="gu1@aeroxteam.fr",
    url="https://github.com/rackspace/pyrax",
    keywords="hubic pyrax cloud openstack",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
    ],
    install_requires=[
        'pyrax>=1.6.4',
    ],
    py_modules=['pyrax_identity_hubic'],
    test_suite='test_pyrax_identity_hubic'
)
