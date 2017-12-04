"""
Nifty-Client
-------------

Nifty Client is the official python client for the Nifty Mobile
Money API.

Please see

 - https://www.nifty.co.ke

"""
from setuptools import setup

with open('README.rst', 'r') as f:
    readme = f.read()

setup(
    name='niftyclient',
    version='0.2.3',
    url='https://bitbucket.org/east36/python-nifty-client',
    license='GPLv3',
    author='Laban Mwangi',
    author_email='lmwangi@east36.co.ke',
    description='Official Python API client for Nifty',
    long_description=readme,
    packages=['niftyclient'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'httpsig_cffi', 'dictobj', 'requests', 'marshmallow'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
