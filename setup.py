# set up basic requirements for droidbot
__author__ = 'liyc'

from setuptools import setup, find_packages
setup(
  name = 'droidbot',
  packages = find_packages(exclude=['docker', 'resources', 'droidbot/tests'
                                    'droidbot_out', 'evaluation_reports', ]), # this must be the same as the name above
  version = '1.0.0a2',
  description = 'A smart Android app exerciser.',
  author = 'Lynn',
  license='MIT',
  author_email = 'pkulyc@gmail.com',
  url = 'https://github.com/lynnlyc/droidbot', # use the URL to the github repo
  download_url = 'https://github.com/lynnlyc/droidbot/tarball/1.0.0a2',
  keywords = ['testing', 'monkey', 'exerciser'], # arbitrary keywords
  classifiers=[
    # How mature is this project? Common values are
    #   3 - Alpha
    #   4 - Beta
    #   5 - Production/Stable
    'Development Status :: 3 - Alpha',

    # Indicate who your project is intended for
    'Intended Audience :: Developers',
    'Topic :: Software Development :: Testing',

    # Pick your license as you wish (should match "license" above)
    'License :: OSI Approved :: MIT License',

    # Specify the Python versions you support here. In particular, ensure
    # that you indicate whether you support Python 2, Python 3 or both.
    'Programming Language :: Python :: 2.7',
  ],
  script_name='start.py',
  entry_points={
    'console_scripts': [
        'droidbot=start:main',
    ],
  },
  # androidviewclient doesnot support pip install, thus we put the directory in ours
  install_requires=['androguard', 'androidviewclient'],
)