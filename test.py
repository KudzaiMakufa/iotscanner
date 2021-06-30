import requests

r = requests.get('http://192.168.0.1/login.htm', auth=('Admin', ''))


print(r.content)

