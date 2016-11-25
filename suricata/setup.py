'''
ampt-monitor-suricata setup
'''

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ampt-monitor-suricata',
    version='0.2.1',
    description='ampt-monitor-suricata, module to read healthcheck alerts from Suricata EVE logs for the AMPT monitor',
    long_description=long_description,
    url='https://github.com/nids-io/ampt-monitor',
    author='AMPT Project',
    author_email='ampt@nids.io',
    license='BSD',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
        'Topic :: System :: Networking :: Monitoring',
    ],
    keywords='ampt, ampt-monitor, ampt-monitor-suricata, suricata, a passive network health monitoring tool',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'dateutils',
        'ujson'
    ],
)
