# set up basic requirements for droidbot
__author__ = 'liyc'

from setuptools import setup, find_packages, findall
import os

setup(
    name='droidbot',
    packages=find_packages(exclude=['droidbot.tests', 'resources',
                                    'droidbot_out', 'evaluation_reports']),
    # this must be the same as the name above
    version='1.0.2b3',
    description='A lightweight UI-guided test input generator for Android.',
    author='Yuanchun Li',
    license='MIT',
    author_email='pkulyc@gmail.com',
    url='https://github.com/honeynet/droidbot',  # use the URL to the github repo
    download_url='https://github.com/honeynet/droidbot/tarball/1.0.2b3',
    keywords=['testing', 'monkey', 'exerciser'],  # arbitrary keywords
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Testing',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2.7',
    ],
    entry_points={
        'console_scripts': [
            'droidbot=droidbot:start',
        ],
    },
    package_data={
        'droidbot': map(lambda x: os.path.relpath(x, 'droidbot'), findall('droidbot/resources/'))
    },
    # androidviewclient doesnot support pip install, thus you should install it with easy_install
    install_requires=['androguard', 'networkx', 'Pillow'],
)
