# completed 2/22/2019 by Alex Clark
# url encodes a plaintext string
# usage: python3 encode.py 'hello, there, mr. grinch!'

from urllib.request import quote 
from sys import argv

print(quote(u'%s' % argv[1]))
