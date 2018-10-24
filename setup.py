#!/usr/bin/env python

from setuptools import setup, find_packages

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
