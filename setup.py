import os
import versioneer
from setuptools import setup

project_name = 'winrmlib'

# versioneer configuration
versioneer.VCS = 'git'
versioneer.versionfile_source = os.path.join('winrmlib', '_version.py')
versioneer.versionfile_build = os.path.join('winrmlib', '_version.py')
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'winrmlib'

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''

requires = [
    "pyopenssl >= 0.14",
    "requests == 2.5.0",
    "ntlmlib >= 0.70",
    "ordereddict",
    "xmltodict"
]

setup(
    name=project_name,
    version=versioneer.get_version(),
    description='Python library for Windows Remote Management with CredSSP and NTLMv2',
    long_description=long_description,
    keywords='winrm winrw ws-man ws-management powershell'.split(' '),
    author='Ian Clegg',
    author_email='ian.clegg@sourcewarp.com',
    url='https://github.com/ianclegg/winrmlib/',
    license='MIT license',
    packages=['winrmlib', 'winrmlib.api'],
    package_data={'winrmlib.api': ['assets/xsd/*.xsd', 'assets/*.wsdl']},
    install_requires=requires,
    cmdclass=versioneer.get_cmdclass(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Clustering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration',
    ],
)
