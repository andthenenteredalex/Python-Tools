# url encodes a plaintext string
# usage: python3 url_encoder.py 'hello, there, mr. grinch!'

from urllib.request import quote 
from sys import argv

print(quote(u'%s' % argv[1]))
