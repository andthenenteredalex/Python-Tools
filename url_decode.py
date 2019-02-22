# completed 11/18/2018 by Alex Clark
# decodes a url encoded string
# usage: python3 decode.py %20some%20string%20this%20is%21%20yay%21%20

from urllib.parse import unquote
from sys import argv

print(unquote(u'%s' % argv[1]))
