# set up basic requirements for droidbot
__author__ = 'liyc'

from distutils.core import setup
setup(
  name = 'droidbot',
  packages = ['droidbot'], # this must be the same as the name above
  version = '1.0.1',
  description = 'A smart Android app exerciser.',
  author = 'Lynn',
  author_email = 'pkulyc@gmail.com',
  url = 'https://github.com/lynnlyc/droidbot', # use the URL to the github repo
  download_url = 'https://github.com/lynnlyc/droidbot/tarball/1.0.1', # I'll explain this in a second
  keywords = ['testing', 'monkey', 'exerciser'], # arbitrary keywords
  classifiers = [],
)