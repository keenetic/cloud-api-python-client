"""
Network Devices Cloud Client API Setup
"""

from setuptools import setup, find_packages

setup(
    name='ndcloudclient',
    version='1.0.0',
    packages=find_packages(),
    url='https://github.com/keenetic/cloud-api-python-client',
    license='',
    author='Keenetic Ltd.',
    author_email='developers@keenetic.com',
    description='NDSS API Client',
    include_package_data=True,
    install_requires=[
        'requests',
        'base58',
        'ecdsa'
    ]
)