#!/usr/bin/env python
"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from setuptools import find_packages, setup

from hathor import __version__

# with open('requirements.txt') as fp:
#     install_requires = fp.read()

setup(
    name='hathor',
    version=__version__,
    description='Hathor Network full-node',
    author='Hathor Team',
    author_email='contact@hathor.network',
    url='https://hathor.network/',
    license='Proprietary',
    entry_points={
        'console_scripts': ['hathor-cli=hathor.cli.main:main'],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
        'License :: Other/Proprietary License',
        'Private :: Do Not Upload',
    ],
    packages=find_packages(exclude=('tests', 'tests.*')),
    # install_requires=install_requires,
)
