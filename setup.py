#!/usr/bin/env python
"""
sentry-gitee
=============

An extension for Sentry which integrates with Gitee. Specifically, it allows
you to easily create issues from events within Sentry.

:copyright: (c) 2015 Pancentric Ltd, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.
"""
from setuptools import setup, find_packages


tests_require = [
    'sentry>=8.0.0',
]

install_requires = []

setup(
    name='sentry-gitee',
    version='0.2.0',
    author='lei2jun',
    author_email='724099654@qq.com',
    url='https://gitee.com/lei2jun/sentry-gitee',
    description='A Sentry extension which integrates with Gitee.',
    long_description=__doc__,
    license='BSD',
    package_dir={'': 'src'},
    packages=find_packages('src'),
    zip_safe=False,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={'test': tests_require},
    include_package_data=True,
    entry_points={
        'sentry.apps': [
            'gitee = sentry_gitee',
        ],
        'sentry.plugins': [
            'gitee = sentry_gitee.plugin:GiteePlugin'
        ],
    },
    classifiers=[
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development'
    ],
)
