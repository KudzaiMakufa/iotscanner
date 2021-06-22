import netifaces
gateways = netifaces.gateways()
default_gateway = gateways['default'][netifaces.AF_INET][0]
print(default_gateway)